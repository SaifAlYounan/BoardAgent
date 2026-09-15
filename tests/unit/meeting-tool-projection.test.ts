import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { describe, expect, it, vi } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import type { SurfacePrincipal, SurfaceToolResult } from "../../artifacts/server/src/ports.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  AGENDA_PREFLIGHT_SQL,
  AGENDA_CONTENT_SQL,
  ATTENDANCE_PREFLIGHT_SQL,
  ATTENDANCE_CONTENT_SQL,
  agendaProjectionCost,
  agendaProjectionPlan,
  attendanceProjectionCost,
  attendanceProjectionPlan,
  loadAdmittedAgenda,
  loadAdmittedAttendance,
  type AgendaProjectionMetadata,
  type AttendanceProjectionMetadata
} from "../../artifacts/server/src/meeting-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  ORIGINAL_AGENDA_SQL,
  ORIGINAL_ATTENDANCE_SQL
} from "../helpers/meeting-tool-original-sql.js";

// Real public parser/registry/caller; synthetic authority and transaction/query port.
// No SQL, RLS, normal storage constraints or native transport execute in this file.
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
type Tool = "get_agenda" | "get_attendance";
const id = (n: number) => `01993600-0000-7000-8000-${String(n).padStart(12, "0")}`;
const sha = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const bytes = (value: unknown) => (value === null ? 0 : Buffer.byteLength(String(value)));
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
function agendaSource() {
  return [1, 2].map((version) => ({
    meeting_id: id(1),
    agenda_version_id: id(10 + version),
    version,
    schema_version: "boardagent.agenda.v1",
    canonical_payload: { threshold: 0.5, nested: [null, { title: 'Synthetic "Δ"' }] } as JsonValue,
    sha256: "a".repeat(64),
    items: [
      {
        item_id: id(23),
        ordinal: 2,
        title: "Last 🙂",
        source_document_version_id: null as string | null,
        source_document_sha256: null as string | null,
        sha256: "c".repeat(64)
      },
      {
        item_id: id(22),
        ordinal: 1,
        title: "Tied second",
        source_document_version_id: id(40),
        source_document_sha256: "d".repeat(64) as string | null,
        sha256: "e".repeat(64)
      },
      {
        item_id: id(21),
        ordinal: 1,
        title: "Tied first",
        source_document_version_id: null as string | null,
        source_document_sha256: null as string | null,
        sha256: "f".repeat(64)
      }
    ],
    created_at: "2026-09-13T00:00:00.000001Z" as string | null
  }));
}
type Agenda = ReturnType<typeof agendaSource>[number];
function attendanceSource() {
  return [
    {
      view: {
        attendance_id: id(51),
        member_id: id(60),
        status: "present",
        source: "secretary_record",
        recorder_member_id: id(61),
        corrects_id: null as string | null,
        correction_reason: null as string | null,
        recorded_at: "2026-09-13T00:00:00.000001Z" as string | null
      },
      raw: "2026-09-13 00:00:00.000001+00"
    },
    {
      view: {
        attendance_id: id(52),
        member_id: id(60),
        status: "absent",
        source: "correction",
        recorder_member_id: id(61),
        corrects_id: id(51) as string | null,
        correction_reason: 'Correct "Δ" 🙂' as string | null,
        recorded_at: "2026-09-13T00:00:00.000002Z" as string | null
      },
      raw: "2026-09-13 00:00:00.000002+00"
    }
  ];
}
type Attendance = ReturnType<typeof attendanceSource>[number];
function orderedAgenda(value: Agenda): Agenda {
  return {
    ...value,
    items: [...value.items].sort(
      (a, b) => a.ordinal - b.ordinal || a.item_id.localeCompare(b.item_id)
    )
  };
}
function orderedAttendance(rows: Attendance[]) {
  return [...rows].sort(
    (a, b) => a.raw.localeCompare(b.raw) || a.view.attendance_id.localeCompare(b.view.attendance_id)
  );
}
function agendaMeasure(view: Agenda): AgendaProjectionMetadata {
  // Independently enumerated ORIGINAL six flat root/six flat item values.
  let s = [
    view.meeting_id,
    view.agenda_version_id,
    view.version,
    view.schema_version,
    view.sha256,
    view.created_at
  ].reduce<number>((n, x) => n + bytes(x), 0);
  for (const item of view.items)
    for (const value of [
      item.item_id,
      item.ordinal,
      item.title,
      item.source_document_version_id,
      item.source_document_sha256,
      item.sha256
    ])
      s += bytes(value);
  const graph = shape(view.canonical_payload);
  return {
    meeting_id: view.meeting_id,
    agenda_version_id: view.agenda_version_id,
    version: String(view.version),
    item_count: String(view.items.length),
    scalar_utf8: String(s),
    normalized_json_utf8: String(Buffer.byteLength(JSON.stringify(view.canonical_payload))),
    json_property_count: String(graph.properties),
    json_container_count: String(graph.containers),
    observation_sha256: sha(JSON.stringify(view))
  };
}
function attendanceMeasure(rows: Attendance[]): AttendanceProjectionMetadata {
  let s = Buffer.byteLength(id(1));
  const tuples: unknown[] = [];
  for (const { view, raw } of rows) {
    const values = [
      view.attendance_id,
      view.member_id,
      view.status,
      view.source,
      view.recorder_member_id,
      view.corrects_id,
      view.correction_reason,
      view.recorded_at
    ];
    for (const value of values) s += bytes(value);
    tuples.push([...values, raw]);
  }
  return {
    meeting_id: id(1),
    record_count: String(rows.length),
    scalar_utf8: String(s),
    observation_sha256: sha(rows.length ? JSON.stringify(tuples) : "")
  };
}
function envelope(tool: Tool, data: JsonValue): JsonValue {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: id(1),
    resource_uri: null,
    data
  };
}
function fixture() {
  const state = {
    agendas: agendaSource(),
    currentVersion: 2,
    attendance: attendanceSource(),
    constructions: 0,
    afterMetadata: undefined as (() => void) | undefined,
    beforeContent: undefined as (() => Promise<void>) | undefined,
    metadataOverride: undefined as unknown[] | undefined,
    contentOverride: undefined as unknown[] | undefined
  };
  const selected = (version: number | null) => {
    const value = state.agendas.find((a) => a.version === (version ?? state.currentVersion));
    return value ? orderedAgenda(value) : undefined;
  };
  const query = vi.fn(async (sql: string, params?: unknown[]) => {
    expect(params?.[0]).toBe(id(1));
    if (sql === AGENDA_PREFLIGHT_SQL) {
      const view = selected(params?.[1] as number | null),
        rows = state.metadataOverride ?? (view ? [agendaMeasure(view)] : []);
      state.afterMetadata?.();
      return { rows };
    }
    if (sql === ATTENDANCE_PREFLIGHT_SQL) {
      const rows = state.metadataOverride ?? [
        attendanceMeasure(orderedAttendance(state.attendance))
      ];
      state.afterMetadata?.();
      return { rows };
    }
    if (
      [
        ORIGINAL_AGENDA_SQL,
        ORIGINAL_ATTENDANCE_SQL,
        AGENDA_CONTENT_SQL,
        ATTENDANCE_CONTENT_SQL
      ].includes(sql)
    )
      await state.beforeContent?.();
    if (sql === ORIGINAL_AGENDA_SQL) {
      const view = selected(params?.[1] as number | null);
      if (view) state.constructions++;
      return { rows: view ? [{ view }] : [] };
    }
    if (sql === ORIGINAL_ATTENDANCE_SQL) {
      state.constructions++;
      return { rows: [{ items: orderedAttendance(state.attendance).map((x) => ({ ...x.view })) }] };
    }
    if (state.contentOverride) return { rows: state.contentOverride };
    if (sql === AGENDA_CONTENT_SQL) {
      const view = selected(params?.[1] as number | null);
      if (!view) return { rows: [] };
      const m = agendaMeasure(view);
      const fits =
        m.agenda_version_id === params?.[2] &&
        m.version === params?.[3] &&
        m.observation_sha256 === params?.[4] &&
        m.item_count === params?.[5] &&
        BigInt(m.scalar_utf8) <= BigInt(String(params?.[6])) &&
        BigInt(m.normalized_json_utf8) <= BigInt(String(params?.[7])) &&
        m.json_property_count === params?.[8] &&
        m.json_container_count === params?.[9];
      if (fits) state.constructions++;
      return { rows: [{ ...m, fits, view: fits ? view : null }] };
    }
    if (sql === ATTENDANCE_CONTENT_SQL) {
      const rows = orderedAttendance(state.attendance),
        m = attendanceMeasure(rows);
      const fits =
        m.record_count === "0" ||
        (m.record_count === params?.[1] &&
          BigInt(m.scalar_utf8) <= BigInt(String(params?.[2])) &&
          m.observation_sha256 === params?.[3]);
      if (fits) state.constructions++;
      return { rows: [{ ...m, fits, items: fits ? rows.map((x) => ({ ...x.view })) : null }] };
    }
    throw new Error("unexpected meeting SQL");
  });
  const client = { query } as unknown as PoolClient,
    repo = new PgSurfaceReadRepository({ fixtureClient: client } as unknown as Pool, {
      cursorKey: Buffer.alloc(32, 1)
    });
  const principal: SurfacePrincipal = {
    organizationId: id(99),
    memberId: id(98),
    serviceOrigin: "https://boardagent.test",
    clientId: id(97),
    protocolClientId: "meeting-unit",
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
    readMeeting(
      client: PoolClient,
      principal: SurfacePrincipal,
      name: string,
      input: Readonly<Record<string, JsonValue>>
    ): Promise<SurfaceToolResult>;
  };
  const liveActor = vi.spyOn(seam, "liveActor").mockResolvedValue({});
  const authorize = vi.spyOn(seam, "authorizeRead").mockReturnValue(undefined);
  vi.spyOn(seam, "dispatch").mockImplementation((connection, actor, name, input) => {
    if (name !== "get_agenda" && name !== "get_attendance")
      throw new Error("out-of-scope dispatch");
    return seam.readMeeting(connection, actor, name, input);
  });
  return {
    state,
    query,
    liveActor,
    authorize,
    selected,
    helper: (tool: Tool, version: number | null = null): Promise<unknown> =>
      tool === "get_agenda"
        ? loadAdmittedAgenda(client, id(1), version)
        : loadAdmittedAttendance(client, id(1)),
    read: (tool: Tool, version: number | null = null) =>
      repo.executeRead(principal, tool, {
        schema_version: TOOL_INPUT_SCHEMA_VERSION,
        meeting_id: id(1),
        ...(tool === "get_agenda" ? { version } : {})
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

describe("meeting tool projection admission", () => {
  for (const tool of ["get_agenda", "get_attendance"] as const)
    it(`refuses public ${tool} before full construction under complete shared occupancy`, async () => {
      const f = fixture(),
        manager = new ResponseAllocationManager(),
        leases = Array.from({ length: 2048 }, () => manager.tryReserve(small()));
      let failure: unknown;
      try {
        try {
          await owned(manager, () => f.read(tool));
        } catch (error) {
          failure = error;
        }
        expect(f.state.constructions, "old caller attempted full projection before admission").toBe(
          0
        );
        expect(failure).toBeInstanceOf(ResponseAllocationUnavailable);
        expect(f.liveActor).toHaveBeenCalledOnce();
        expect(f.authorize).toHaveBeenCalledOnce();
        expect(f.query.mock.calls).toHaveLength(1);
        expect(f.query.mock.calls[0]?.[0]).toBe(
          tool === "get_agenda" ? AGENDA_PREFLIGHT_SQL : ATTENDANCE_PREFLIGHT_SQL
        );
      } finally {
        for (const lease of leases) lease.release();
      }
      expect(manager.accounting.usedUnits).toBe(0);
    });
  for (const version of [null, 1, 99])
    it(`preserves the complete original agenda envelope for selector ${version}`, async () => {
      const f = fixture(),
        view = f.selected(version),
        expected = envelope("get_agenda", { agenda: view ?? null });
      const actual = await owned(new ResponseAllocationManager(), () =>
        f.read("get_agenda", version)
      );
      expect(actual).toEqual(expected);
      expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
      expect(canonicalJson(actual)).toBe(canonicalJson(expected));
      if (view)
        expect((actual.data as { agenda: Agenda }).agenda.items.map((x) => x.item_id)).toEqual([
          id(21),
          id(22),
          id(23)
        ]);
    });
  for (const count of [0, 2])
    it(`preserves all original attendance fields and the ${count}-record envelope`, async () => {
      const f = fixture();
      f.state.attendance = attendanceSource().slice(0, count).reverse();
      const expected = envelope("get_attendance", {
        meeting_id: id(1),
        records: attendanceSource()
          .slice(0, count)
          .map((x) => x.view)
      });
      const actual = await owned(new ResponseAllocationManager(), () => f.read("get_attendance"));
      expect(actual).toEqual(expected);
      expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
      expect(canonicalJson(actual)).toBe(canonicalJson(expected));
    });
  for (const collaborator of ["liveActor", "authorize"] as const)
    it(`keeps ${collaborator} denial ahead of either SQL projection`, async () => {
      for (const tool of ["get_agenda", "get_attendance"] as const) {
        const f = fixture(),
          error = new Error("synthetic initial denial");
        if (collaborator === "liveActor") f.liveActor.mockRejectedValueOnce(error);
        else
          f.authorize.mockImplementationOnce(() => {
            throw error;
          });
        await expect(owned(new ResponseAllocationManager(), () => f.read(tool))).rejects.toBe(
          error
        );
        expect(f.query).not.toHaveBeenCalled();
      }
    });
  for (const tool of ["get_agenda", "get_attendance"] as const)
    it(`refuses known oversized ${tool} metadata before content`, async () => {
      const f = fixture();
      f.state.metadataOverride = [
        {
          ...(tool === "get_agenda"
            ? agendaMeasure(f.selected(null)!)
            : attendanceMeasure(orderedAttendance(f.state.attendance))),
          scalar_utf8: "999999999"
        }
      ];
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper(tool))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.query).toHaveBeenCalledOnce();
      expect(f.state.constructions).toBe(0);
    });
  it("bounds original agenda JSON, full SDK graph and nested wire using independent literal oracles", () => {
    for (const payload of [
      null,
      false,
      0,
      10000000000000000,
      '\u0001\n\\"🙂',
      [],
      {},
      { deep: [{ a: [], b: { c: [null] } }], many: Array.from({ length: 300 }, () => ({})) }
    ] as JsonValue[]) {
      const view = orderedAgenda(agendaSource()[1]!);
      view.canonical_payload = payload;
      view.items[0]!.title = '\u0001\n\\\"🙂'.repeat(257);
      const m = agendaMeasure(view),
        cost = agendaProjectionCost(m),
        plan = agendaProjectionPlan(m),
        body = envelope("get_agenda", { agenda: view });
      const wire = {
          content: [{ type: "text", text: JSON.stringify(body) }],
          structuredContent: body
        },
        graph = shape(wire),
        jsonGraph = shape(payload);
      expect(BigInt(Buffer.byteLength(JSON.stringify(view)))).toBeLessThanOrEqual(
        BigInt(cost.jsonUpperBytes)
      );
      expect(graph.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
      expect(graph.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
      expect(cost.propertyCount).toBe(String(31 + 18 + jsonGraph.properties));
      expect(cost.objectOrArrayCount).toBe(String(7 + 3 + jsonGraph.containers));
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
    }
  });
  it("counts small-byte high-container JSON separately from serialized bytes", () => {
    const view = orderedAgenda(agendaSource()[1]!);
    view.canonical_payload = Array.from({ length: 1000 }, () => ({}));
    view.items = [];
    const m = agendaMeasure(view),
      cost = agendaProjectionCost(m);
    expect(shape(view.canonical_payload)).toEqual({ properties: 0, containers: 1001 });
    expect(m.normalized_json_utf8).toBe("3001");
    expect(cost.objectOrArrayCount).toBe("1008");
    const flat = { ...m, json_container_count: "0" };
    expect(agendaProjectionPlan(m).units).toBeGreaterThanOrEqual(agendaProjectionPlan(flat).units);
    expect(
      512 *
        (Number(cost.objectOrArrayCount) - Number(agendaProjectionCost(flat).objectOrArrayCount))
    ).toBe(512512);
  });
  it("bounds complete attendance history escaping and full SDK graph independently", () => {
    const rows = attendanceSource();
    rows[1]!.view.correction_reason = '\u0001\n\\\"🙂'.repeat(1024);
    rows[0]!.view.recorded_at = null;
    const m = attendanceMeasure(rows),
      cost = attendanceProjectionCost(m),
      plan = attendanceProjectionPlan(m),
      data = { meeting_id: id(1), records: rows.map((x) => x.view) };
    const body = envelope("get_attendance", data),
      wire = { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body },
      graph = shape(wire);
    expect(BigInt(Buffer.byteLength(JSON.stringify(data)))).toBeLessThanOrEqual(
      BigInt(cost.jsonUpperBytes)
    );
    expect(graph.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
    expect(graph.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
    expect(cost.propertyCount).toBe("41");
    expect(cost.objectOrArrayCount).toBe("9");
    expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
  });
  it("crosses the exact agenda one-unit boundary without adding a public JSON restriction", () => {
    const m = agendaMeasure(orderedAgenda(agendaSource()[1]!));
    Object.assign(m, {
      item_count: "0",
      scalar_utf8: "184",
      normalized_json_utf8: "116071",
      json_property_count: "0",
      json_container_count: "0"
    });
    expect(agendaProjectionCost(m)).toEqual({
      jsonUpperBytes: "117344",
      propertyCount: "31",
      objectOrArrayCount: "7"
    });
    expect(65536 + 8 * (117344 + 4096) + 256 * 31 + 512 * 7).toBe(1048576);
    expect(agendaProjectionPlan(m).units).toBe(1);
    expect(agendaProjectionPlan({ ...m, normalized_json_utf8: "116072" }).units).toBe(2);
  });
  it("allows a 1920-unit attendance metric with 100 small reads and refuses one added UTF8 byte", () => {
    const m = {
        meeting_id: id(1),
        record_count: "161",
        scalar_utf8: "41927495",
        observation_sha256: sha("boundary")
      },
      cost = attendanceProjectionCost(m);
    expect(cost).toEqual({
      jsonUpperBytes: "251593184",
      propertyCount: "1313",
      objectOrArrayCount: "168"
    });
    expect(65536 + 8 * (251593184 + 4096) + 256 * 1313 + 512 * 168).toBe(2013265920);
    const manager = new ResponseAllocationManager(),
      smallLeases = Array.from({ length: 100 }, () => manager.tryReserve(small()));
    let lease: ReturnType<typeof manager.tryReserve> | undefined;
    try {
      const plan = attendanceProjectionPlan(m);
      expect(plan.units).toBe(1920);
      lease = manager.tryReserve(plan);
      expect(manager.accounting.usedUnits).toBe(2020);
      lease.release();
      lease = undefined;
      expect(manager.accounting.usedUnits).toBe(100);
      const over = attendanceProjectionPlan({ ...m, scalar_utf8: "41927496" });
      expect(over.units).toBe(1921);
      expect(() => manager.tryReserve(over)).toThrow(ResponseAllocationUnavailable);
    } finally {
      lease?.release();
      for (const smallLease of smallLeases) smallLease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
  });
  it("binds the current agenda selector but leaves explicit version selection independent", async () => {
    const changed = fixture();
    changed.state.afterMetadata = () => {
      changed.state.currentVersion = 1;
    };
    await expect(
      owned(new ResponseAllocationManager(), () => changed.helper("get_agenda"))
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(changed.state.constructions).toBe(0);
    const explicit = fixture();
    explicit.state.afterMetadata = () => {
      explicit.state.currentVersion = 1;
    };
    const loaded = await owned(new ResponseAllocationManager(), () =>
      explicit.helper("get_agenda", 2)
    );
    expect((loaded as { view: JsonValue }[]).map((row) => row.view)).toEqual([
      explicit.selected(2)
    ]);
  });
  it("rejects equal-cost normalized agenda JSON replacement despite unchanged stored hash", async () => {
    const f = fixture(),
      before = agendaMeasure(f.selected(null)!);
    f.state.afterMetadata = () => {
      const view = f.state.agendas[1]!;
      view.canonical_payload = { threshold: 0.6, nested: [null, { title: 'Synthetic "Δ"' }] };
      const after = agendaMeasure(orderedAgenda(view)),
        { observation_sha256: oldHash, ...oldCost } = before,
        { observation_sha256: newHash, ...newCost } = after;
      expect(newCost).toEqual(oldCost);
      expect(newHash).not.toBe(oldHash);
      expect(view.sha256).toBe("a".repeat(64));
    };
    await expect(
      owned(new ResponseAllocationManager(), () => f.helper("get_agenda"))
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(f.state.constructions).toBe(0);
  });
  it("rejects visible agenda child growth and partial loss, but preserves missing-root null", async () => {
    for (const change of ["growth", "subset", "absent"]) {
      const f = fixture();
      f.state.afterMetadata = () => {
        if (change === "growth")
          f.state.agendas[1]!.items.push({ ...f.state.agendas[1]!.items[0]!, item_id: id(24) });
        else if (change === "subset") f.state.agendas[1]!.items.pop();
        else f.state.agendas = [];
      };
      if (change === "absent")
        expect(await owned(new ResponseAllocationManager(), () => f.helper("get_agenda"))).toEqual(
          []
        );
      else
        await expect(
          owned(new ResponseAllocationManager(), () => f.helper("get_agenda"))
        ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
    }
  });
  it("rejects nonempty attendance replacement, partial loss and new history", async () => {
    for (const change of ["same-width", "subset", "growth", "raw-time"]) {
      const f = fixture();
      f.state.afterMetadata = () => {
        if (change === "same-width")
          f.state.attendance[1]!.view.correction_reason =
            f.state.attendance[1]!.view.correction_reason!.replace("Correct", "Changed");
        else if (change === "subset") f.state.attendance.pop();
        else if (change === "growth")
          f.state.attendance.push({
            ...f.state.attendance[1]!,
            view: { ...f.state.attendance[1]!.view, attendance_id: id(53) }
          });
        else f.state.attendance[1]!.raw = "2026-09-13 00:00:00.000003+00";
      };
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper("get_attendance"))
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(f.state.constructions).toBe(0);
    }
  });
  it("returns fresh empty attendance after complete visibility loss and rejects empty-to-visible growth", async () => {
    const lost = fixture();
    lost.state.afterMetadata = () => {
      lost.state.attendance = [];
    };
    expect(
      await owned(new ResponseAllocationManager(), () => lost.helper("get_attendance"))
    ).toEqual([]);
    const grew = fixture();
    grew.state.attendance = [];
    grew.state.afterMetadata = () => {
      grew.state.attendance = attendanceSource();
    };
    await expect(
      owned(new ResponseAllocationManager(), () => grew.helper("get_attendance"))
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(grew.state.constructions).toBe(0);
  });
  it("rejects malformed metadata before content and keeps overflow a bounded capacity error", async () => {
    for (const change of ["multiple", "selector", "version", "zero-json"]) {
      const f = fixture(),
        m = agendaMeasure(f.selected(null)!);
      f.state.metadataOverride = [m];
      if (change === "multiple") f.state.metadataOverride.push({ ...m });
      else if (change === "selector") f.state.metadataOverride = [{ ...m, meeting_id: id(999) }];
      else if (change === "version") f.state.metadataOverride = [{ ...m, version: "0" }];
      else f.state.metadataOverride = [{ ...m, normalized_json_utf8: "0" }];
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper("get_agenda"))
      ).rejects.toBeInstanceOf(TypeError);
      expect(f.query).toHaveBeenCalledOnce();
    }
    expect(() =>
      attendanceProjectionCost({
        meeting_id: id(1),
        record_count: "00",
        scalar_utf8: "36",
        observation_sha256: sha("")
      })
    ).toThrow(TypeError);
    expect(() =>
      attendanceProjectionCost({
        meeting_id: id(1),
        record_count: "0",
        scalar_utf8: "9".repeat(25),
        observation_sha256: sha("")
      })
    ).toThrow(ResponseAllocationUnavailable);
  });
  it("rejects loaded parent/header/item-count tampering and attendance empty-header forgery", async () => {
    for (const change of ["id", "digest", "items"]) {
      const f = fixture(),
        view = f.selected(null)!,
        m = agendaMeasure(view),
        row = { ...m, fits: true, view };
      if (change === "id") row.agenda_version_id = id(999);
      else if (change === "digest") row.observation_sha256 = sha("forged");
      else view.items = [];
      f.state.contentOverride = [row];
      await expect(
        owned(new ResponseAllocationManager(), () => f.helper("get_agenda"))
      ).rejects.toBeInstanceOf(TypeError);
    }
    const f = fixture();
    f.state.contentOverride = [
      {
        meeting_id: id(1),
        record_count: "0",
        scalar_utf8: "36",
        observation_sha256: sha("forged"),
        fits: true,
        items: []
      }
    ];
    await expect(
      owned(new ResponseAllocationManager(), () => f.helper("get_attendance"))
    ).rejects.toBeInstanceOf(TypeError);
  });
  it("uses tool-only zero-raw private plans and accepts a one-byte normalized scalar", () => {
    const m = agendaMeasure(orderedAgenda(agendaSource()[1]!)),
      plan = agendaProjectionPlan({
        ...m,
        normalized_json_utf8: "1",
        json_property_count: "0",
        json_container_count: "0"
      });
    expect(plan.canonicalBytes).toBe(0);
    expect(() => responseAllocationPlan({ ...plan, canonicalBytes: 1 })).toThrow(TypeError);
    expect(() => responseAllocationPlan({ ...plan, representation: "resource" })).toThrow(
      TypeError
    );
  });
  it("prevents either content query when disconnect happens after preflight", async () => {
    for (const tool of ["get_agenda", "get_attendance"] as const) {
      const f = fixture(),
        manager = new ResponseAllocationManager(),
        controller = new AbortController(),
        owner = manager.openRequest(controller.signal);
      f.state.afterMetadata = () => controller.abort();
      try {
        await expect(owner.produce(() => f.helper(tool))).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(f.query).toHaveBeenCalledOnce();
      } finally {
        try {
          owner.nativeTerminal();
        } finally {
          owner.collectorSettled();
        }
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
  });
  it("retains a held attendance producer after early disconnect and both settlement markers", async () => {
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
    const produced = owner.produce(() => f.helper("get_attendance"));
    const settled = produced.then(
      (value) => ({ ok: true as const, value }),
      (error) => ({ ok: false as const, error })
    );
    let deadline: ReturnType<typeof setTimeout> | undefined, failure: unknown;
    try {
      await Promise.race([
        entered.promise,
        settled.then((outcome) => {
          throw new Error("producer settled before content gate", {
            cause: outcome.ok ? undefined : outcome.error
          });
        }),
        new Promise<never>((_resolve, reject) => {
          deadline = setTimeout(() => reject(new Error("content gate entry timed out")), 2000);
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
    } catch (error) {
      failure = error;
    } finally {
      if (deadline !== undefined) clearTimeout(deadline);
      release.release();
      controller.abort();
      try {
        owner.nativeTerminal();
      } finally {
        owner.collectorSettled();
      }
      let cleanupDeadline: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          settled,
          new Promise<never>((_resolve, reject) => {
            cleanupDeadline = setTimeout(
              () => reject(new Error("producer cleanup timed out")),
              2000
            );
          })
        ]);
      } catch (error) {
        failure =
          failure === undefined
            ? error
            : new AggregateError([failure, error], "meeting test and producer cleanup failed");
      } finally {
        if (cleanupDeadline !== undefined) clearTimeout(cleanupDeadline);
      }
    }
    if (failure !== undefined) throw failure;
  });
  it("retains even empty attendance until both producer and native settlement finish", async () => {
    const f = fixture();
    f.state.attendance = [];
    const manager = new ResponseAllocationManager(),
      owner = manager.openRequest(new AbortController().signal);
    try {
      expect(await owner.produce(() => f.helper("get_attendance"))).toEqual([]);
      expect(manager.accounting.usedUnits).toBe(1);
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBe(1);
      owner.nativeTerminal();
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      try {
        owner.nativeTerminal();
      } finally {
        owner.collectorSettled();
      }
    }
  });
});
