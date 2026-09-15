import { expect, it } from "vitest";
import type { PoolClient } from "pg";
import {
  canonicalJson,
  TOOL_INPUT_SCHEMA_VERSION,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
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
  responseAllocationPlan,
  type ResponseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import { seedMeetingToolProjectionFixture } from "../helpers/meeting-tool-projection-fixture.js";
import { meetingProjectionPrincipal } from "../helpers/meeting-projection-principal.js";
import {
  ORIGINAL_AGENDA_SQL,
  ORIGINAL_ATTENDANCE_SQL
} from "../helpers/meeting-tool-original-sql.js";
import {
  originalAgendaOracle,
  originalAttendanceOracle,
  meetingOracleShape
} from "../helpers/meeting-tool-pg-oracle.js";

type Kind = "agenda" | "attendance";
interface Queries {
  original: string;
  preflight: string;
  content: string;
}
const queries: Record<Kind, Queries> = {
  agenda: {
    original: ORIGINAL_AGENDA_SQL,
    preflight: AGENDA_PREFLIGHT_SQL,
    content: AGENDA_CONTENT_SQL
  },
  attendance: {
    original: ORIGINAL_ATTENDANCE_SQL,
    preflight: ATTENDANCE_PREFLIGHT_SQL,
    content: ATTENDANCE_CONTENT_SQL
  }
};
function replaceOnce(sql: string, from: string, to: string) {
  expect(sql.split(from)).toHaveLength(2);
  return sql.replace(from, to);
}
function envelope(kind: Kind, meetingId: string, value: JsonValue): JsonValue {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: kind === "agenda" ? "get_agenda" : "get_attendance",
    status: "ok",
    reference: meetingId,
    resource_uri: null,
    data: kind === "agenda" ? { agenda: value } : { meeting_id: meetingId, records: value }
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
function boundWire(
  kind: Kind,
  meetingId: string,
  value: JsonValue,
  cost: { jsonUpperBytes: string; propertyCount: string; objectOrArrayCount: string },
  plan: ResponseAllocationPlan
) {
  const body = envelope(kind, meetingId, value),
    wire = { content: [{ type: "text", text: JSON.stringify(body) }], structuredContent: body };
  const view = kind === "agenda" ? value : { meeting_id: meetingId, records: value },
    graph = meetingOracleShape(wire);
  expect(BigInt(Buffer.byteLength(JSON.stringify(view)))).toBeLessThanOrEqual(
    BigInt(cost.jsonUpperBytes)
  );
  expect(graph.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
  expect(graph.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
  expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
}
function deadline<T>(work: Promise<T>, label: string, milliseconds = 5000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    work,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), milliseconds);
    })
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

it("admits original agenda and attendance views with actual scalar binding and guarded fresh construction", async () => {
  await withMigratedDatabase("meeting_tool_projection", async (pool) => {
    const fixture = await seedMeetingToolProjectionFixture(pool),
      actor = fixture.secretary;
    const transaction = <T>(body: (client: PoolClient) => Promise<T>, context = actor.context) =>
      withRequestTransaction(pool, context, body, { assumeRole: "boardagent_server" });
    const manager = new ResponseAllocationManager(),
      reports: unknown[] = [];
    const catalog = (
      await pool.query(`select c.relname,c.relrowsecurity,c.relforcerowsecurity,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indnkeyatts=1 and a.attname='id') as id_pk
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public'
      and c.relname in ('meetings','agenda_versions','agenda_items','meeting_attendance') order by c.relname`)
    ).rows;
    expect(catalog).toHaveLength(4);
    for (const row of catalog)
      expect(row).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true, id_pk: true });
    const uniqueIndexes = (
      await pool.query(`select c.relname,i.indisprimary,i.indisvalid,
      array(select a.attname::text from unnest(i.indkey::smallint[]) with ordinality as key(attnum,ordinality)
        join pg_attribute a on a.attrelid=c.oid and a.attnum=key.attnum where key.ordinality<=i.indnkeyatts order by key.ordinality) as columns,
      pg_get_expr(i.indpred,i.indrelid) as predicate
      from pg_index i join pg_class c on c.oid=i.indrelid join pg_namespace n on n.oid=c.relnamespace
      where n.nspname='public' and i.indisunique and c.relname in ('agenda_versions','agenda_items','meeting_attendance') order by c.relname,i.indexrelid`)
    ).rows;
    expect(
      uniqueIndexes.some(
        (row) =>
          row.relname === "agenda_versions" &&
          row.indisvalid &&
          JSON.stringify(row.columns) === JSON.stringify(["meeting_id", "version"])
      )
    ).toBe(true);
    expect(
      uniqueIndexes.some(
        (row) =>
          row.relname === "agenda_items" &&
          row.indisvalid &&
          JSON.stringify(row.columns) === JSON.stringify(["agenda_version_id", "ordinal"])
      )
    ).toBe(true);
    expect(
      await transaction(async (client) => (await client.query("select current_user")).rows)
    ).toEqual([{ current_user: "boardagent_server" }]);

    async function own<T>(work: () => Promise<T>) {
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
    async function read(
      kind: Kind,
      meetingId: string,
      options: {
        version?: number | null;
        afterMetadata?: (client: PoolClient) => Promise<unknown>;
        beforeContent?: (client: PoolClient) => Promise<unknown>;
        sql?: Queries;
        context?: typeof actor.context;
        coordinated?: boolean;
      } = {}
    ) {
      const owner = manager.openRequest(new AbortController().signal),
        baseline = manager.accounting.usedUnits;
      const actual = options.sql ?? queries[kind];
      let metadataCalls = 0,
        contentCalls = 0,
        held = baseline,
        failure: unknown,
        value: unknown;
      try {
        value = await owner.produce(() =>
          transaction(async (client) => {
            const proxy = Object.create(client) as PoolClient;
            proxy.query = (async (sql: string, parameters?: unknown[]) => {
              if (sql === queries[kind].preflight) {
                metadataCalls++;
                const reply = await client.query(actual.preflight, parameters);
                await options.afterMetadata?.(client);
                return reply;
              }
              if (sql === queries[kind].content) {
                contentCalls++;
                await options.beforeContent?.(client);
                return client.query(actual.content, parameters);
              }
              throw new Error("unexpected meeting loader query");
            }) as PoolClient["query"];
            return kind === "agenda"
              ? loadAdmittedAgenda(proxy, meetingId, options.version ?? null)
              : loadAdmittedAttendance(proxy, meetingId);
          }, options.context ?? actor.context)
        );
      } catch (error) {
        failure = error;
      } finally {
        held = manager.accounting.usedUnits;
        try {
          owner.nativeTerminal();
        } finally {
          owner.collectorSettled();
        }
      }
      reports.push({
        kind,
        meetingId,
        version: options.version ?? null,
        metadataCalls,
        contentCalls,
        held,
        finalUnits: manager.accounting.usedUnits,
        coordinated: options.coordinated ?? false,
        failed: failure !== undefined
      });
      // The one coordinated pair checks shared zero only after BOTH requests end.
      try {
        expect(metadataCalls).toBe(1);
        if (!options.coordinated) expect(manager.accounting.usedUnits).toBe(baseline);
      } catch (error) {
        if (failure !== undefined)
          throw new AggregateError([failure, error], "meeting SQL and accounting failed");
        throw error;
      }
      if (failure !== undefined) throw failure;
      return { value, metadataCalls, contentCalls, held, baseline };
    }
    async function admittedQuery(
      sql: string,
      parameters: unknown[],
      plan: ResponseAllocationPlan,
      name?: string,
      mode?: "force_custom_plan" | "force_generic_plan"
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      try {
        return await owner.produce(async () => {
          owner.reserve(plan);
          return transaction(async (client) => {
            if (mode) await client.query(`set local plan_cache_mode=${mode}`);
            return client.query({
              text: sql,
              values: parameters,
              ...(name === undefined ? {} : { name })
            });
          });
        });
      } finally {
        try {
          owner.nativeTerminal();
        } finally {
          owner.collectorSettled();
        }
      }
    }
    async function verifyAgenda(meetingId: string, version: number | null, sql = queries.agenda) {
      const oracle = await transaction((client) =>
        originalAgendaOracle(client, meetingId, version, sql.original)
      );
      const preflight = await transaction(
        async (client) =>
          (await client.query<AgendaProjectionMetadata>(sql.preflight, [meetingId, version])).rows
      );
      expect(preflight).toEqual(oracle ? [oracle.metadata] : []);
      const admitted = await read("agenda", meetingId, { version, sql });
      const values = (admitted.value as readonly { view: JsonValue }[]).map((row) => row.view);
      expect(values).toEqual(oracle ? [oracle.view] : []);
      expect(canonicalJson(values)).toBe(canonicalJson(oracle ? [oracle.view] : []));
      if (oracle) {
        const plan = agendaProjectionPlan(oracle.metadata);
        boundWire("agenda", meetingId, oracle.view, agendaProjectionCost(oracle.metadata), plan);
        expect(admitted.held).toBe(plan.units);
      } else expect(admitted.held).toBe(0);
      reports.push({
        proof: "agenda original scalar/hash parity",
        meetingId,
        version,
        metadata: oracle?.metadata ?? null,
        normalizedJsonText: oracle?.normalizedJsonText ?? null
      });
      return oracle;
    }
    async function verifyAttendance(meetingId: string, sql = queries.attendance) {
      const oracle = await transaction((client) =>
        originalAttendanceOracle(client, meetingId, sql.original)
      );
      expect(
        await transaction(
          async (client) =>
            (await client.query<AttendanceProjectionMetadata>(sql.preflight, [meetingId])).rows
        )
      ).toEqual([oracle.metadata]);
      const admitted = await read("attendance", meetingId, { sql });
      expect(admitted.value).toEqual(oracle.items);
      expect(canonicalJson(admitted.value as JsonValue)).toBe(canonicalJson(oracle.items));
      const plan = attendanceProjectionPlan(oracle.metadata);
      boundWire(
        "attendance",
        meetingId,
        oracle.items,
        attendanceProjectionCost(oracle.metadata),
        plan
      );
      expect(admitted.held).toBe(plan.units);
      reports.push({
        proof: "attendance original scalar/hash parity",
        meetingId,
        metadata: oracle.metadata
      });
      return oracle;
    }

    const current = await verifyAgenda(fixture.meetingId, null),
      explicit = await verifyAgenda(fixture.meetingId, 1);
    expect(current?.metadata.agenda_version_id).toBe(fixture.amendedAgendaId);
    expect(explicit?.metadata.agenda_version_id).toBe(fixture.originalAgendaId);
    expect(current?.metadata.item_count).toBe("3");
    expect(explicit?.metadata.item_count).toBe("3");
    expect(await verifyAgenda(fixture.meetingId, 2147483647)).toBeNull();
    const attended = await verifyAttendance(fixture.meetingId),
      empty = await verifyAttendance(fixture.emptyMeetingId);
    expect(attended.metadata.record_count).toBe("2");
    expect(empty.metadata.record_count).toBe("0");
    expect(attended.items).toEqual([
      expect.objectContaining({
        attendance_id: fixture.originalAttendanceId,
        status: "present",
        source: "secretary_record",
        corrects_id: null
      }),
      expect.objectContaining({
        attendance_id: fixture.currentAttendanceId(),
        status: "excused",
        corrects_id: fixture.originalAttendanceId
      })
    ]);
    if (!current || !explicit) throw new Error("normal agenda fixture is absent");
    const agendaView = current.view as Record<string, JsonValue>;
    expect(agendaView["items"]).toEqual([
      expect.objectContaining({
        ordinal: 1,
        source_document_version_id: null,
        source_document_sha256: null
      }),
      expect.objectContaining({
        ordinal: 2,
        source_document_version_id: fixture.documentVersionId,
        source_document_sha256: fixture.documentSha256
      }),
      expect.objectContaining({ ordinal: 3 })
    ]);

    // Direct request-context negatives compare the original and admitted visibility;
    // they are not a substitute for the separate public live-principal prologue.
    for (const [label, context] of [
      ["wrong-organization", { ...actor.context, organizationId: testId(285098) }],
      ["empty-board-scope", { ...actor.context, boardIds: [] }]
    ] as const) {
      const oldAgenda = await transaction(
        (client) => originalAgendaOracle(client, fixture.meetingId, null),
        context
      );
      const oldAttendance = await transaction(
        (client) => originalAttendanceOracle(client, fixture.meetingId),
        context
      );
      expect(oldAgenda).toBeNull();
      expect(oldAttendance.items).toEqual([]);
      const deniedAgenda = await read("agenda", fixture.meetingId, { context });
      const deniedAttendance = await read("attendance", fixture.meetingId, { context });
      expect(deniedAgenda.value).toEqual([]);
      expect(deniedAgenda.held).toBe(0);
      expect(deniedAgenda.contentCalls).toBe(0);
      expect(deniedAttendance.value).toEqual([]);
      expect(deniedAttendance.held).toBe(1);
      reports.push({
        proof: "original and admitted request-context visibility",
        context: label,
        agendaRows: 0,
        attendanceRows: 0
      });
    }

    // Real public prologue uses a constrained session and the actual nine-field resolver.
    const principal = await meetingProjectionPrincipal(pool, actor);
    const repository = new PgSurfaceReadRepository(pool, {
      cursorKey: Buffer.alloc(32, 0x73),
      transaction: { assumeRole: "boardagent_server" }
    });
    const publicCases: [Kind, string, number | null, JsonValue][] = [
      ["agenda", fixture.meetingId, null, current.view],
      ["agenda", fixture.meetingId, 1, explicit.view],
      ["agenda", fixture.meetingId, 2147483647, null],
      ["attendance", fixture.meetingId, null, attended.items],
      ["attendance", fixture.emptyMeetingId, null, empty.items]
    ];
    for (const [kind, id, version, value] of publicCases) {
      const input =
        kind === "agenda"
          ? { schema_version: TOOL_INPUT_SCHEMA_VERSION, meeting_id: id, version }
          : { schema_version: TOOL_INPUT_SCHEMA_VERSION, meeting_id: id };
      const reply = await own(() =>
        repository.executeRead(
          principal,
          kind === "agenda" ? "get_agenda" : "get_attendance",
          input
        )
      );
      expect(reply).toEqual(envelope(kind, id, value));
      expect(JSON.stringify(reply)).toBe(JSON.stringify(envelope(kind, id, value)));
      expect(canonicalJson(reply)).toBe(canonicalJson(envelope(kind, id, value)));
    }

    // Occupy BOTH lanes: a full large lane alone still admits these one-unit reads.
    const occupied = manager.openRequest(new AbortController().signal);
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 2048; i++) occupied.reserve(small());
      });
      expect(manager.accounting.usedUnits).toBe(2048);
      for (const kind of ["agenda", "attendance"] as const) {
        const start = reports.length;
        await expect(read(kind, fixture.meetingId)).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(reports[start]).toMatchObject({
          metadataCalls: 1,
          contentCalls: 0,
          held: 2048,
          finalUnits: 2048
        });
      }
    } finally {
      try {
        occupied.nativeTerminal();
      } finally {
        occupied.collectorSettled();
      }
    }
    expect(manager.accounting.usedUnits).toBe(0);

    const am = current.metadata,
      ap = agendaProjectionPlan(am),
      tm = attended.metadata,
      tp = attendanceProjectionPlan(tm);
    const agendaParameters: unknown[] = [
      fixture.meetingId,
      null,
      am.agenda_version_id,
      am.version,
      am.observation_sha256,
      am.item_count,
      am.scalar_utf8,
      am.normalized_json_utf8,
      am.json_property_count,
      am.json_container_count
    ];
    const attendanceParameters: unknown[] = [
      fixture.meetingId,
      tm.record_count,
      tm.scalar_utf8,
      tm.observation_sha256
    ];
    const agendaFalse: [string, number, unknown][] = [
      ["selected-id", 2, testId(285099)],
      ["version", 3, String(Number(am.version) + 1)],
      ["private-observation", 4, "0".repeat(64)],
      ["item-count", 5, String(Number(am.item_count) + 1)],
      ["scalar-utf8", 6, (BigInt(am.scalar_utf8) - 1n).toString()],
      ["normalized-json-utf8", 7, (BigInt(am.normalized_json_utf8) - 1n).toString()],
      ["json-properties", 8, String(Number(am.json_property_count) + 1)],
      ["json-containers", 9, String(Number(am.json_container_count) + 1)]
    ];
    const attendanceFalse: [string, number, unknown][] = [
      ["record-count", 1, String(Number(tm.record_count) + 1)],
      ["scalar-utf8", 2, (BigInt(tm.scalar_utf8) - 1n).toString()],
      ["private-observation", 3, "0".repeat(64)]
    ];
    const dynamicFault = (otherwise: string) =>
      `case when length(gated.observation_sha256)>=0 then (1/(length(gated.observation_sha256)-64))::text else ${otherwise} end`;
    const faultSql = [
      {
        kind: "agenda" as const,
        constructor: "root",
        sql: replaceOnce(
          AGENDA_CONTENT_SQL,
          "'meeting_id',agenda.meeting_id",
          `'meeting_id',${dynamicFault("agenda.meeting_id::text")}`
        ),
        parameters: agendaParameters,
        plan: ap,
        controls: agendaFalse
      },
      {
        kind: "agenda" as const,
        constructor: "item",
        sql: replaceOnce(
          AGENDA_CONTENT_SQL,
          "'title',item.title",
          `'title',${dynamicFault("item.title")}`
        ),
        parameters: agendaParameters,
        plan: ap,
        controls: agendaFalse
      },
      {
        kind: "attendance" as const,
        constructor: "record",
        sql: replaceOnce(
          ATTENDANCE_CONTENT_SQL,
          "'status',attendance.status",
          `'status',${dynamicFault("attendance.status::text")}`
        ),
        parameters: attendanceParameters,
        plan: tp,
        controls: attendanceFalse
      }
    ];
    const faults: unknown[] = [];
    let falseCount = 0,
      trueCount = 0;
    for (const mode of ["force_custom_plan", "force_generic_plan"] as const)
      for (const variant of faultSql) {
        const name = `meeting_${mode}_${variant.constructor}`;
        for (const [label, index, value] of variant.controls) {
          const parameters = [...variant.parameters];
          parameters[index] = value;
          const result = await admittedQuery(variant.sql, parameters, variant.plan, name, mode);
          expect(result.rows).toHaveLength(1);
          expect(result.rows[0]).toMatchObject({
            fits: false,
            [variant.kind === "agenda" ? "view" : "items"]: null
          });
          falseCount++;
          faults.push({ mode, constructor: variant.constructor, gate: label, fits: false });
        }
        await expect(
          admittedQuery(variant.sql, variant.parameters, variant.plan, name, mode)
        ).rejects.toMatchObject({ code: "22012" });
        trueCount++;
        faults.push({ mode, constructor: variant.constructor, gate: "true", code: "22012" });
      }
    expect({ falseCount, trueCount }).toEqual({ falseCount: 38, trueCount: 6 });
    const freshEmpty = await admittedQuery(
      ATTENDANCE_CONTENT_SQL,
      [fixture.emptyMeetingId, "999", "0", "0".repeat(64)],
      tp
    );
    expect(freshEmpty.rows).toEqual([
      expect.objectContaining({ fits: true, record_count: "0", scalar_utf8: "36", items: [] })
    ]);

    // These query-only source substitutions cover values unreachable through the strict
    // normal agenda writer. They transform the exact authorized bytea source identically
    // in the verbatim original and both measured statements; storage is unchanged.
    const normalized = "convert_from(agenda.canonical_payload,'UTF8')::jsonb";
    function jsonVariant(raw: string): Queries {
      expect(raw.includes("$synthetic$")).toBe(false);
      const transformed = `convert_from(case when length(agenda.id::text)>0 then convert_to($synthetic$${raw}$synthetic$,'UTF8') else agenda.canonical_payload end,'UTF8')::jsonb`;
      return {
        original: replaceOnce(ORIGINAL_AGENDA_SQL, normalized, transformed),
        preflight: replaceOnce(AGENDA_PREFLIGHT_SQL, normalized, transformed),
        content: replaceOnce(AGENDA_CONTENT_SQL, normalized, transformed)
      };
    }
    for (const raw of [
      " 0",
      "null",
      "[9999999999999999]",
      '{"a":[{},[],{"b":[[],{}]}],"escaped":"\\u0001\\n\\\"Δ"}'
    ]) {
      const value = await verifyAgenda(fixture.meetingId, null, jsonVariant(raw));
      if (!value) throw new Error("query-only agenda unexpectedly absent");
      if (raw === " 0") expect(value.metadata.normalized_json_utf8).toBe("1");
      if (raw === "[9999999999999999]") {
        const body = (value.view as Record<string, JsonValue>)["canonical_payload"];
        expect(body).toEqual([10000000000000000]);
        expect(value.normalizedJsonText).toBe("[9999999999999999]");
        expect(Buffer.byteLength(JSON.stringify(body))).toBe(
          Number(value.metadata.normalized_json_utf8) + 1
        );
      }
    }
    const malformedJson = jsonVariant("{");
    const badUtf8 = `convert_from(case when length(agenda.id::text)>0 then decode('ff','hex') else agenda.canonical_payload end,'UTF8')::jsonb`;
    const malformedUtf8 = {
      original: replaceOnce(ORIGINAL_AGENDA_SQL, normalized, badUtf8),
      preflight: replaceOnce(AGENDA_PREFLIGHT_SQL, normalized, badUtf8),
      content: replaceOnce(AGENDA_CONTENT_SQL, normalized, badUtf8)
    };
    for (const [variant, code] of [
      [malformedJson, "22P02"],
      [malformedUtf8, "22021"]
    ] as const) {
      await expect(
        transaction((client) =>
          originalAgendaOracle(client, fixture.meetingId, null, variant.original)
        )
      ).rejects.toMatchObject({ code });
      await expect(read("agenda", fixture.meetingId, { sql: variant })).rejects.toMatchObject({
        code
      });
      await expect(admittedQuery(variant.content, agendaParameters, ap)).rejects.toMatchObject({
        code
      });
    }

    // Query-only partial visibility, using one identical authorized source filter in
    // original/preflight/content. This is not a policy change or an RLS claim.
    const relation = "meeting_attendance as attendance";
    const filtered = `(select * from meeting_attendance where id::text is distinct from nullif(current_setting('boardagent_test.hidden_attendance_id',true),'')) as attendance`;
    const partial = {
      original: replaceOnce(ORIGINAL_ATTENDANCE_SQL, relation, filtered),
      preflight: replaceOnce(ATTENDANCE_PREFLIGHT_SQL, relation, filtered),
      content: replaceOnce(ATTENDANCE_CONTENT_SQL, relation, filtered)
    };
    const visibleBefore = await transaction((client) =>
      originalAttendanceOracle(client, fixture.meetingId, partial.original)
    );
    expect(visibleBefore.items).toHaveLength(2);
    await expect(
      read("attendance", fixture.meetingId, {
        sql: partial,
        afterMetadata: async (client) => {
          await client.query("select set_config('boardagent_test.hidden_attendance_id',$1,true)", [
            fixture.originalAttendanceId
          ]);
          const visible = await originalAttendanceOracle(
            client,
            fixture.meetingId,
            partial.original
          );
          expect(visible.items).toHaveLength(1);
          expect(visible.items[0]).toMatchObject({ attendance_id: fixture.currentAttendanceId() });
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);

    // Both growth operations use the already smoke-tested normal fixture commands.
    await expect(
      read("agenda", fixture.meetingId, { afterMetadata: () => fixture.amendAgain() })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const revised = await verifyAgenda(fixture.meetingId, null);
    expect(revised?.metadata.version).toBe("3");
    expect((await verifyAgenda(fixture.meetingId, 1))?.view).toEqual(explicit.view);
    await expect(
      read("attendance", fixture.meetingId, { afterMetadata: () => fixture.correctAgain() })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const corrected = await verifyAttendance(fixture.meetingId);
    expect(corrected.items).toHaveLength(3);
    expect(fixture.commands).toHaveLength(8);

    // Two actual fresh-content statements after committed token revocation. Initial
    // public authority is checked above; these are in-flight direct-loader/RLS controls.
    const entered = gate(),
      release = gate();
    let enteredCount = 0;
    const beforeContent = async () => {
      if (++enteredCount === 2) entered.release();
      await release.promise;
    };
    const pending = [
      read("agenda", fixture.meetingId, { beforeContent, coordinated: true }),
      read("attendance", fixture.meetingId, { beforeContent, coordinated: true })
    ];
    const produced = Promise.allSettled(pending);
    const premature = Promise.race(pending).then(() => {
      throw new Error("an RLS read settled before the content gate");
    });
    let revokedResults: Awaited<typeof produced> | undefined;
    const revocationFailures: unknown[] = [];
    try {
      await deadline(Promise.race([entered.promise, premature]), "RLS content gates did not enter");
      expect(manager.accounting.usedUnits).toBe(2);
      const revoked = await pool.query(
        "update access_token_records set revoked_at=transaction_timestamp() where id=$1 and revoked_at is null returning id",
        [actor.accessTokenRecordId]
      );
      expect(revoked.rowCount).toBe(1);
      const oldAgenda = await transaction((client) =>
        originalAgendaOracle(client, fixture.meetingId, null)
      );
      const oldAttendance = await transaction((client) =>
        originalAttendanceOracle(client, fixture.meetingId)
      );
      reports.push({
        proof: "actual original RLS after committed exact token revocation",
        agendaVisible: oldAgenda !== null,
        attendanceCount: oldAttendance.items.length
      });
      expect(oldAgenda).toBeNull();
      expect(oldAttendance.items).toEqual([]);
      release.release();
      revokedResults = await deadline(produced, "RLS readers did not settle");
      for (const result of revokedResults) if (result.status === "rejected") throw result.reason;
      expect(revokedResults[0]).toMatchObject({ status: "fulfilled", value: { value: [] } });
      expect(revokedResults[1]).toMatchObject({ status: "fulfilled", value: { value: [] } });
    } catch (error) {
      revocationFailures.push(error);
    } finally {
      release.release();
      try {
        await deadline(produced, "RLS cleanup did not settle");
      } catch (error) {
        revocationFailures.push(error);
      }
    }
    if (revocationFailures.length)
      throw new AggregateError(revocationFailures, "RLS body or cleanup failed");
    expect(manager.accounting.usedUnits).toBe(0);
    console.log(
      JSON.stringify({
        proof: "agenda and attendance actual-role projection admission",
        normalCommands: fixture.commands.length,
        publicCalls: publicCases.length,
        catalog,
        uniqueIndexes,
        falseCount,
        trueCount,
        faults,
        reports,
        finalUnits: manager.accounting.usedUnits,
        limits: [
          "small normal fixture plus labeled query-only variants",
          "modeled owner terminal/collector signals, not native transport",
          "no PostgreSQL workspace or RSS qualification",
          "in-flight exact-token RLS observation, not all-role authorization closure"
        ]
      })
    );
  });
}, 90000);
