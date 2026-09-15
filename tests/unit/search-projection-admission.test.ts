import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import type { JsonValue } from "../../lib/contracts/src/canonical.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  SEARCH_PREFLIGHT_SQL,
  SEARCH_CONTENT_SQL,
  loadAdmittedSearchProjection,
  searchProjectionPlan,
  type SearchProjectionMetadata
} from "../../artifacts/server/src/search-projection-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";

const id = (n: number) => `01993400-0000-7000-8000-${String(n).padStart(12, "0")}`;
const at = "2026-09-12T16:00:00.000000Z";
const input = { boardId: id(1), query: "needle", cursorAt: null, cursorId: null, limit: 2 };

function fixture() {
  const metadata = {
    id: id(3),
    row_version: "1",
    version_id: id(4),
    version: "1",
    sha256: "a".repeat(64),
    search_version_id: id(4),
    search_sha256: "a".repeat(64),
    cursor_at: at,
    scalar_utf8: "500",
    snippet_utf8: "20",
    rank_json_bytes: "8"
  } satisfies SearchProjectionMetadata;
  const item = {
    document_id: metadata.id,
    version_id: metadata.version_id,
    title: "Search title",
    media_type: "text/plain; charset=utf-8",
    document_schema: null,
    byte_length: 10_485_760,
    sha256: metadata.sha256,
    rank: 0.1,
    snippet: "needle plain snippet",
    resource_uri: `board://${input.boardId}/documents/${metadata.id}/versions/1`
  };
  let fullConstruction = 0;
  const query = vi.fn(
    async (sql: string, _values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }> => {
      if (sql === SEARCH_PREFLIGHT_SQL) return { rows: [{ ...metadata }] };
      if (sql === SEARCH_CONTENT_SQL) {
        fullConstruction += 1;
        return { rows: [{ fits: true, cursor_id: metadata.id, cursor_at: at, item }] };
      }
      // The original combined search supports the positive control and records
      // premature construction for the saturation baseline, instead of throwing
      // merely because the old SQL string differs from the proposed query.
      if (sql.startsWith("with matched as materialized (") && sql.includes("ts_headline(")) {
        fullConstruction += 1;
        return { rows: [{ cursor_id: metadata.id, cursor_at: at, item }] };
      }
      throw new Error("unexpected search fixture query");
    }
  );
  return {
    metadata,
    item,
    query,
    client: { query } as unknown as PoolClient,
    constructions: () => fullConstruction
  };
}

function privateSearch(client: PoolClient, limit = 2) {
  const repository = new PgSurfaceReadRepository({} as Pool, { cursorKey: Buffer.alloc(32, 1) });
  const seam = repository as unknown as {
    readDocumentMetadata(
      client: PoolClient,
      principal: SurfacePrincipal,
      tool: string,
      input: Record<string, JsonValue>
    ): Promise<{ data: JsonValue }>;
  };
  return seam.readDocumentMetadata(
    client,
    { organizationId: id(99), memberId: id(2) } as SurfacePrincipal,
    "search_documents",
    { board_id: id(1), query: "needle", cursor: null, limit }
  );
}

const projection = (json: string) =>
  responseAllocationPlan({
    kind: "search_projection",
    representation: "tool",
    sourceId: "search-frontier",
    sourceVersion: "1",
    sha256: "b".repeat(64),
    canonicalBytes: 0,
    listProjection: { jsonUpperBytes: json, propertyCount: "0", objectOrArrayCount: "0" }
  });

describe("search projection preconstruction admission", () => {
  it("refuses a saturated search before full row construction", async () => {
    const f = fixture();
    const manager = new ResponseAllocationManager();
    const held = [manager.tryReserve(projection("251645952"))];
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
      await expect(owner.produce(() => privateSearch(f.client))).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(f.constructions()).toBe(0);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.query.mock.calls[0]?.[0]).toBe(SEARCH_PREFLIGHT_SQL);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
      for (const lease of held) lease.release();
    }
  });

  it("preserves the exact positive page and ten-field search item", async () => {
    const f = fixture();
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      const result = await owner.produce(() => privateSearch(f.client));
      expect(result.data).toEqual({ items: [f.item], next_cursor: null });
      expect(Object.keys(f.item)).toHaveLength(10);
      expect(f.constructions()).toBe(1);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("refuses measured oversized snippets before constructing any row JSON", async () => {
    const f = fixture();
    f.query.mockImplementationOnce(async () => ({
      rows: [{ ...f.metadata, snippet_utf8: "50000000" }]
    }));
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedSearchProjection(f.client, input))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(f.constructions()).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("requires a live owner before any preflight", async () => {
    const f = fixture();
    await expect(loadAdmittedSearchProjection(f.client, input)).rejects.toThrow(
      "native response allocation owner"
    );
    expect(f.query).not.toHaveBeenCalled();
  });

  it("cancellation during scalar measurement prevents the content statement", async () => {
    const f = fixture();
    const controller = new AbortController();
    f.query.mockImplementationOnce(async () => {
      controller.abort();
      return { rows: [f.metadata] };
    });
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(controller.signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedSearchProjection(f.client, input))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledTimes(1);
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("retains the reservation after a fresh global gate refusal until settlement", async () => {
    const f = fixture();
    const original = f.query.getMockImplementation()!;
    f.query.mockImplementation(async (sql, values) =>
      sql === SEARCH_CONTENT_SQL
        ? { rows: [{ fits: false, cursor_id: f.metadata.id, cursor_at: at, item: null }] }
        : original(sql, values)
    );
    const manager = new ResponseAllocationManager();
    const owner = manager.openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedSearchProjection(f.client, input))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("allows an authorized vanished subset without substituting a new identity", async () => {
    const f = fixture();
    f.query.mockImplementationOnce(async () => ({
      rows: [f.metadata, { ...f.metadata, id: id(5) }]
    }));
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    try {
      expect(await owner.produce(() => loadAdmittedSearchProjection(f.client, input))).toEqual([
        { item: f.item, cursor_at: at, cursor_id: f.metadata.id }
      ]);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("still performs a fresh gate for an empty initial frontier", async () => {
    const f = fixture();
    f.query.mockImplementation(async (sql) =>
      sql === SEARCH_PREFLIGHT_SQL
        ? { rows: [] }
        : { rows: [{ fits: true, cursor_id: null, cursor_at: null, item: null }] }
    );
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    try {
      expect(await owner.produce(() => loadAdmittedSearchProjection(f.client, input))).toEqual([]);
      expect(f.query).toHaveBeenCalledTimes(2);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("rejects a loaded digest that does not match the admitted version", async () => {
    const f = fixture();
    const original = f.query.getMockImplementation()!;
    f.query.mockImplementation(async (sql, values) =>
      sql === SEARCH_CONTENT_SQL
        ? {
            rows: [
              {
                fits: true,
                cursor_id: f.metadata.id,
                cursor_at: at,
                item: { ...f.item, sha256: "d".repeat(64) }
              }
            ]
          }
        : original(sql, values)
    );
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedSearchProjection(f.client, input))
      ).rejects.toThrow("loaded search identity");
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("rejects duplicate scalar roots before content construction", async () => {
    const f = fixture();
    f.query.mockImplementationOnce(async () => ({ rows: [f.metadata, f.metadata] }));
    const owner = new ResponseAllocationManager().openRequest(new AbortController().signal);
    try {
      await expect(
        owner.produce(() => loadAdmittedSearchProjection(f.client, input))
      ).rejects.toThrow("invalid search frontier");
      expect(f.constructions()).toBe(0);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("charges 501 large-source tiny-snippet rows before the 500-item page and cursor", async () => {
    const f = fixture();
    const frontier = Array.from({ length: 501 }, (_, n) => ({ ...f.metadata, id: id(1000 - n) }));
    const manager = new ResponseAllocationManager();
    const expectedPlan = searchProjectionPlan({ ...input, limit: 500 }, frontier);
    const query = vi.fn(async (sql: string, values: unknown[]) => {
      expect(values[4]).toBe(501);
      if (sql === SEARCH_PREFLIGHT_SQL) return { rows: frontier };
      if (sql === SEARCH_CONTENT_SQL) {
        expect(JSON.parse(values[5] as string)).toHaveLength(501);
        expect(manager.accounting.usedUnits).toBe(expectedPlan.units);
        return {
          rows: frontier.map((row) => ({
            fits: true,
            cursor_id: row.id,
            cursor_at: at,
            item: {
              ...f.item,
              document_id: row.id,
              resource_uri: `board://${input.boardId}/documents/${row.id}/versions/1`
            }
          }))
        };
      }
      if (sql.startsWith("with matched as materialized (") && sql.includes("ts_headline("))
        return {
          rows: frontier.map((row) => ({
            cursor_id: row.id,
            cursor_at: at,
            item: {
              ...f.item,
              document_id: row.id,
              resource_uri: `board://${input.boardId}/documents/${row.id}/versions/1`
            }
          }))
        };
      throw new Error("unexpected maximum search page query");
    });
    const owner = manager.openRequest(new AbortController().signal);
    try {
      const result = await owner.produce(() =>
        privateSearch({ query } as unknown as PoolClient, 500)
      );
      const page = result.data as { items: (typeof f.item)[]; next_cursor: string };
      expect(page.items).toHaveLength(500);
      expect(page.items.map((row) => row.document_id)).toEqual(
        frontier.slice(0, 500).map((row) => row.id)
      );
      expect(page.items.every((row) => row.byte_length === 10_485_760)).toBe(true);
      expect(page.next_cursor.length).toBeGreaterThan(0);
      expect(expectedPlan.canonicalBytes).toBe(0);
      expect(expectedPlan.units).toBeLessThan(100);
    } finally {
      owner.nativeTerminal();
      owner.collectorSettled();
    }
  });

  it("admits the exact 1920-unit boundary and refuses one additional JSON byte", () => {
    const plan = projection("251645952");
    const independentlyComputed = 65_536n + 8n * (251_645_952n + 4_096n);
    expect(independentlyComputed).toBe(1920n * 1_048_576n);
    expect(plan.units).toBe(1920);
    const manager = new ResponseAllocationManager();
    const lease = manager.tryReserve(plan);
    lease.release();
    const over = projection("251645953");
    expect(over.units).toBe(1921);
    expect(() => manager.tryReserve(over)).toThrow(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
  });

  it("keeps one hundred small measured searches eligible beside a maximum projection", () => {
    const manager = new ResponseAllocationManager();
    const held = [manager.tryReserve(projection("251645952"))];
    const small = searchProjectionPlan(input, [fixture().metadata]);
    expect(small.units).toBe(1);
    try {
      for (let n = 0; n < 100; n += 1) held.push(manager.tryReserve(small));
      expect(manager.accounting).toEqual({ usedUnits: 2020, largeUsedUnits: 1920 });
    } finally {
      for (const lease of held) lease.release();
    }
  });

  it.each(["01", "-1"])("rejects malformed scalar %s before planning", (value) => {
    expect(() =>
      searchProjectionPlan(input, [{ ...fixture().metadata, snippet_utf8: value }])
    ).toThrow(TypeError);
  });

  it("returns bounded capacity refusal for an oversized decimal aggregate", () => {
    expect(() =>
      searchProjectionPlan(input, [{ ...fixture().metadata, snippet_utf8: "1".repeat(25) }])
    ).toThrow(ResponseAllocationUnavailable);
  });

  it("requires tool representation and zero canonical bytes", () => {
    const base = projection("100");
    expect(() => responseAllocationPlan({ ...base, representation: "resource" })).toThrow(
      TypeError
    );
    expect(() => responseAllocationPlan({ ...base, canonicalBytes: 1 })).toThrow(TypeError);
  });

  it("does not add a search reservation growth path", () => {
    const manager = new ResponseAllocationManager();
    const held = manager.tryReserve(projection("100"));
    try {
      expect(() => held.increase(projection("200"))).toThrow(TypeError);
      expect(manager.accounting.usedUnits).toBe(1);
    } finally {
      held.release();
    }
  });

  it("bounds independently serialized adversarial flat items and both MCP copies", () => {
    const alphabet = ["\\", '"', "\n", "\r", "\t", "\u0001", "\u001f", "Ω", "漢", "😀", "<b>", "x"];
    for (let n = 0; n < 128; n += 1) {
      const f = fixture();
      const text = Array.from(
        { length: n + 1 },
        (_, i) => alphabet[(i * 7 + n) % alphabet.length]
      ).join("");
      const item = {
        ...f.item,
        title: text,
        document_schema: n % 2 ? text : null,
        snippet: text,
        rank: n % 2 ? 1.401298464324817e-45 : 3.4028234663852886e38
      };
      // Explicitly enumerate the actual returned fields and cursor values;
      // JSON.stringify is the independent size oracle, not a copy of the bound.
      const scalarValues = [
        item.document_id,
        item.version_id,
        item.title,
        item.media_type,
        item.document_schema ?? "",
        String(item.byte_length),
        item.sha256,
        item.resource_uri,
        at,
        item.document_id
      ];
      const metadata = {
        ...f.metadata,
        scalar_utf8: String(scalarValues.reduce((sum, value) => sum + Buffer.byteLength(value), 0)),
        snippet_utf8: String(Buffer.byteLength(item.snippet)),
        rank_json_bytes: "128"
      };
      const plan = searchProjectionPlan(input, [metadata]);
      const rows = [{ item, cursor_at: at, cursor_id: item.document_id }];
      const result = {
        schema_version: "boardagent.tool-result.v1",
        tool: "search_documents",
        status: "ok",
        reference: null,
        resource_uri: null,
        data: { items: [item], next_cursor: null }
      };
      const wire = {
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: result
      };
      expect(Buffer.byteLength(JSON.stringify(rows))).toBeLessThanOrEqual(
        Number(plan.listProjection!.jsonUpperBytes)
      );
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
      const seen = new Set<object>();
      let properties = 0;
      const stack: unknown[] = [rows, result];
      while (stack.length) {
        const value = stack.pop();
        if (typeof value !== "object" || value === null || seen.has(value)) continue;
        seen.add(value);
        if (!Array.isArray(value)) properties += Object.keys(value).length;
        stack.push(...Object.values(value));
      }
      expect(properties).toBeLessThanOrEqual(Number(plan.listProjection!.propertyCount));
      expect(seen.size).toBeLessThanOrEqual(Number(plan.listProjection!.objectOrArrayCount));
    }
  });
});
