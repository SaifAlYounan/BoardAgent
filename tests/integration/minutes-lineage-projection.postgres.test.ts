import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  MINUTES_LINEAGE_PREFLIGHT_SQL,
  MINUTES_LINEAGE_CONTENT_SQL,
  loadAdmittedMinutesLineage,
  minutesLineageProjectionPlan,
  minutesLineageProjectionCost,
  type MinutesLineageMetadata
} from "../../artifacts/server/src/minutes-lineage-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  seedMinutesLineageFixture,
  excludeMinutesLineageEndpoint
} from "../helpers/minutes-lineage-fixture.js";
import { ORIGINAL_MINUTES_LINEAGE_SQL } from "../helpers/minutes-lineage-original-sql.js";

type Cycle = Readonly<Record<string, JsonValue>>;
const sha = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const keys = [
  "correction_cycle_id",
  "original_minutes_id",
  "replacement_minutes_id",
  "reason",
  "secretary_member_id",
  "created_at"
];
function cycles(value: unknown): Cycle[] {
  if (!Array.isArray(value)) throw new Error("original lineage array absent");
  for (const row of value) {
    if (row === null || typeof row !== "object" || Array.isArray(row))
      throw new Error("original lineage row invalid");
    expect(Object.keys(row).sort()).toEqual([...keys].sort());
  }
  return value as Cycle[];
}
function totalUtf8(minutesId: string, rows: readonly Cycle[]) {
  let total = Buffer.byteLength(minutesId);
  for (const row of rows)
    for (const value of [
      row["correction_cycle_id"],
      row["original_minutes_id"],
      row["replacement_minutes_id"],
      row["reason"],
      row["secretary_member_id"],
      row["created_at"]
    ]) {
      if (value !== null && typeof value !== "string")
        throw new Error("lineage flat value is not text/null");
      total += value === null ? 0 : Buffer.byteLength(value);
    }
  return total;
}
function envelope(minutesId: string, rows: readonly Cycle[]): JsonValue {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: "get_minutes_lineage",
    status: "ok",
    reference: minutesId,
    resource_uri: null,
    data: { minutes_id: minutesId, correction_cycles: rows.map((row) => ({ ...row })) }
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

it("admits exact minutes lineage through normal corrections with complete fresh gates and endpoint RLS", async () => {
  await withMigratedDatabase("minutes_lineage_projection", async (pool) => {
    const fixture = await seedMinutesLineageFixture(pool),
      actor = fixture.secretary,
      minutesId = fixture.middleId;
    const transaction = <T>(work: (client: PoolClient) => Promise<T>, context = actor.context) =>
      withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
    const catalog = (
      await pool.query(`select c.relrowsecurity,c.relforcerowsecurity,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=i.indrelid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indnkeyatts=1 and a.attname='id') as id_pk,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=i.indrelid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisunique and i.indisvalid and i.indpred is null and i.indexprs is null
          and i.indnkeyatts=1 and a.attname='original_minutes_id') as unique_original,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=i.indrelid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisunique and i.indisvalid and i.indpred is null and i.indexprs is null
          and i.indnkeyatts=1 and a.attname='replacement_minutes_id') as unique_replacement
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname='minutes_correction_cycles'`)
    ).rows;
    expect(catalog).toEqual([
      {
        relrowsecurity: true,
        relforcerowsecurity: true,
        id_pk: true,
        unique_original: true,
        unique_replacement: true
      }
    ]);
    expect(
      await transaction(async (client) => (await client.query("select current_user")).rows)
    ).toEqual([{ current_user: "boardagent_server" }]);
    async function original(id = minutesId, context = actor.context) {
      return transaction(
        async (client) =>
          cycles((await client.query(ORIGINAL_MINUTES_LINEAGE_SQL, [id])).rows[0]?.items),
        context
      );
    }
    const one = await original();
    expect(one).toHaveLength(1);
    expect(fixture.currentTip()).toEqual({ minutesId, state: "finalized" });
    const reports: Array<{
      metadata: number;
      content: number;
      held: number;
      after: number;
      fits: unknown;
      error: string | null;
    }> = [];
    async function read(
      options: {
        manager?: ResponseAllocationManager;
        id?: string;
        context?: typeof actor.context;
        afterMetadata?: () => Promise<void>;
      } = {}
    ) {
      const manager = options.manager ?? new ResponseAllocationManager(),
        owner = manager.openRequest(new AbortController().signal);
      let metadata = 0,
        content = 0,
        fits: unknown = null,
        failed = false,
        failure: unknown,
        value: JsonValue[] | undefined,
        held = 0;
      const before = manager.accounting.usedUnits;
      try {
        value = await owner.produce(() =>
          transaction(async (client) => {
            const proxy = {
              query: async (sql: string, parameters?: unknown[]) => {
                if (sql === MINUTES_LINEAGE_PREFLIGHT_SQL) {
                  metadata++;
                  const result = await client.query(sql, parameters);
                  await options.afterMetadata?.();
                  return result;
                }
                if (sql !== MINUTES_LINEAGE_CONTENT_SQL)
                  throw new Error("unexpected lineage helper SQL");
                content++;
                const result = await client.query(sql, parameters);
                fits = result.rows[0]?.fits;
                return result;
              }
            } as unknown as PoolClient;
            return loadAdmittedMinutesLineage(proxy, options.id ?? minutesId);
          }, options.context ?? actor.context)
        );
      } catch (error) {
        failed = true;
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
        metadata,
        content,
        held,
        after: manager.accounting.usedUnits,
        fits,
        error: failed ? String(failure) : null
      });
      if (failed) {
        if (manager.accounting.usedUnits !== before)
          throw new AggregateError(
            [failure, new Error("lineage reservation did not settle")],
            "query failure and settlement mismatch"
          );
        throw failure;
      }
      expect(manager.accounting.usedUnits).toBe(before);
      expect(metadata).toBe(1);
      expect(content).toBe(1);
      expect(held).toBe(before + 1);
      return cycles(value);
    }
    // A supported correction commits between the metadata and content statements.
    await expect(read({ afterMetadata: fixture.appendSuccessor })).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(reports.at(-1)).toMatchObject({
      metadata: 1,
      content: 1,
      held: 1,
      after: 0,
      fits: false
    });
    expect(fixture.currentTip()).toEqual({
      minutesId: fixture.replacementId,
      state: "published_review"
    });
    expect(fixture.commands).toHaveLength(12);
    const expected = await original();
    expect(expected).toHaveLength(2);
    expect(
      expected.map((row) => [row["original_minutes_id"], row["replacement_minutes_id"]])
    ).toEqual([
      [fixture.originalId, minutesId],
      [minutesId, fixture.replacementId]
    ]);
    const observed = await transaction(
      async (client) =>
        (await client.query<MinutesLineageMetadata>(MINUTES_LINEAGE_PREFLIGHT_SQL, [minutesId]))
          .rows
    );
    expect(observed).toHaveLength(2);
    for (const [index, row] of expected.entries()) {
      const metadata = observed[index];
      if (!metadata) throw new Error("lineage metadata omitted a row");
      expect(metadata).toMatchObject({
        correction_cycle_id: row["correction_cycle_id"],
        original_minutes_id: row["original_minutes_id"],
        replacement_minutes_id: row["replacement_minutes_id"],
        secretary_member_id: row["secretary_member_id"],
        created_at: row["created_at"],
        cycle_count: "2"
      });
      expect(metadata.reason_utf8).toBe(String(Buffer.byteLength(String(row["reason"]))));
      expect(metadata.reason_sha256).toBe(sha(String(row["reason"])));
      expect(typeof metadata.raw_created_at).toBe("string");
      const timestamp = await transaction(
        async (client) =>
          (
            await client.query(
              `select created_at::text as raw,
        created_at=$2::timestamptz as exact,created_at=($2::timestamptz+interval '1 microsecond') as shifted
        from minutes_correction_cycles where id=$1`,
              [metadata.correction_cycle_id, metadata.raw_created_at]
            )
          ).rows
      );
      expect(timestamp).toEqual([{ raw: metadata.raw_created_at, exact: true, shifted: false }]);
    }
    const scalar = totalUtf8(minutesId, expected),
      plan = minutesLineageProjectionPlan(minutesId, observed);
    const cost = minutesLineageProjectionCost({ cycle_count: "2", scalar_utf8: String(scalar) });
    const received = await read();
    expect(received).toEqual(expected);
    expect(canonicalJson(envelope(minutesId, received))).toBe(
      canonicalJson(envelope(minutesId, expected))
    );
    expect(JSON.stringify(envelope(minutesId, received))).toBe(
      JSON.stringify(envelope(minutesId, expected))
    );
    expect(
      Buffer.byteLength(JSON.stringify({ minutes_id: minutesId, correction_cycles: expected }))
    ).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
    const controlManager = new ResponseAllocationManager(),
      controlOwner = controlManager.openRequest(new AbortController().signal);
    try {
      const control = await controlOwner.produce(async () => {
        controlOwner.reserve(plan);
        return transaction(
          async (client) =>
            (
              await client.query(MINUTES_LINEAGE_CONTENT_SQL, [
                minutesId,
                JSON.stringify(observed),
                "2",
                String(scalar)
              ])
            ).rows[0]
        );
      });
      expect(control).toMatchObject({
        cycle_count: "2",
        scalar_utf8: String(scalar),
        fits: true,
        items: expected
      });
      expect(controlManager.accounting.usedUnits).toBe(1);
    } finally {
      try {
        controlOwner.nativeTerminal();
      } finally {
        controlOwner.collectorSettled();
      }
    }
    expect(controlManager.accounting.usedUnits).toBe(0);
    // The small fixture also needs all reserved small units occupied, not just1920.
    const saturated = new ResponseAllocationManager(),
      leases = Array.from({ length: 2048 }, () => saturated.tryReserve(small()));
    try {
      await expect(read({ manager: saturated })).rejects.toBeInstanceOf(
        ResponseAllocationUnavailable
      );
      expect(reports.at(-1)).toMatchObject({ metadata: 1, content: 0, held: 2048, after: 2048 });
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(saturated.accounting.usedUnits).toBe(0);
    // The runtime-dependent division is inside the separate full constructor.
    // False gates must skip it; true gates must expose exact22012 under both plans.
    const fault = MINUTES_LINEAGE_CONTENT_SQL.replace(
      "jsonb_build_object(\n    'correction_cycle_id'",
      "jsonb_build_object('fault',1/(length(cycle.reason)-length(cycle.reason))) || jsonb_build_object(\n    'correction_cycle_id'"
    );
    expect(fault).not.toBe(MINUTES_LINEAGE_CONTENT_SQL);
    const fieldNames = [
      "correction_cycle_id",
      "original_minutes_id",
      "replacement_minutes_id",
      "secretary_member_id",
      "reason_utf8",
      "reason_sha256",
      "created_at",
      "raw_created_at"
    ];
    const falseControls: Array<{ mode: string; field: string; fits: boolean }> = [];
    for (const mode of ["force_custom_plan", "force_generic_plan"]) {
      for (const field of ["count", "scalar", ...fieldNames]) {
        const tuples = observed.map((row) => ({ ...row }));
        let count = "2",
          bytes = String(scalar);
        if (field === "count") count = "1";
        else if (field === "scalar") bytes = String(scalar - 1);
        else if (field === "reason_utf8")
          tuples[0]!.reason_utf8 = String(Number(tuples[0]!.reason_utf8) + 1);
        else if (field === "reason_sha256") tuples[0]!.reason_sha256 = "f".repeat(64);
        else if (field === "created_at") tuples[0]!.created_at = "unmatched formatted time";
        else if (field === "raw_created_at")
          tuples[0]!.raw_created_at = await transaction(
            async (client) =>
              (
                await client.query<{ value: string }>(
                  "select ($1::timestamptz+interval '1 microsecond')::text as value",
                  [tuples[0]!.raw_created_at]
                )
              ).rows[0]!.value
          );
        else (tuples[0] as unknown as Record<string, unknown>)[field] = testId(334_000);
        const manager = new ResponseAllocationManager(),
          owner = manager.openRequest(new AbortController().signal);
        try {
          const rows = await owner.produce(async () => {
            owner.reserve(plan);
            return transaction(async (client) => {
              await client.query(`set local plan_cache_mode='${mode}'`);
              return (
                await client.query({
                  name: `lineage-fault-${mode}`,
                  text: fault,
                  values: [minutesId, JSON.stringify(tuples), count, bytes]
                })
              ).rows;
            });
          });
          expect(rows).toEqual([
            { cycle_count: "2", scalar_utf8: String(scalar), fits: false, items: null }
          ]);
          falseControls.push({ mode, field, fits: false });
          expect(manager.accounting.usedUnits).toBe(1);
        } finally {
          try {
            owner.nativeTerminal();
          } finally {
            owner.collectorSettled();
          }
        }
        expect(manager.accounting.usedUnits).toBe(0);
      }
      const manager = new ResponseAllocationManager(),
        owner = manager.openRequest(new AbortController().signal);
      try {
        await expect(
          owner.produce(async () => {
            owner.reserve(plan);
            return transaction(async (client) => {
              await client.query(`set local plan_cache_mode='${mode}'`);
              return client.query({
                name: `lineage-fault-${mode}`,
                text: fault,
                values: [minutesId, JSON.stringify(observed), "2", String(scalar)]
              });
            });
          })
        ).rejects.toMatchObject({ code: "22012" });
      } finally {
        try {
          owner.nativeTerminal();
        } finally {
          owner.collectorSettled();
        }
      }
      expect(manager.accounting.usedUnits).toBe(0);
    }
    for (const context of [
      { ...actor.context, organizationId: testId(334_001) },
      { ...actor.context, boardIds: [] }
    ]) {
      const hidden = await original(minutesId, context);
      expect(hidden).toEqual([]);
      expect(await read({ context })).toEqual(hidden);
    }
    const absent = testId(334_002);
    expect(await original(absent)).toEqual([]);
    expect(await read({ id: absent })).toEqual([]);
    // Separate endpoint exclusions affect the incoming original and outgoing replacement.
    const removedFirst = await read({
      afterMetadata: () => excludeMinutesLineageEndpoint(pool, actor, fixture.originalId, 335_000)
    });
    const surviving = await original();
    expect(surviving).toHaveLength(1);
    expect(removedFirst).toEqual(surviving);
    expect(surviving[0]?.["replacement_minutes_id"]).toBe(fixture.replacementId);
    expect(await read()).toEqual(surviving);
    await expect(
      read({
        afterMetadata: () =>
          excludeMinutesLineageEndpoint(pool, actor, fixture.replacementId, 335_100)
      })
    ).resolves.toEqual([]);
    expect(await original()).toEqual([]);
    expect(await read()).toEqual([]);
    console.log(
      JSON.stringify({
        scope:
          "actual role/helper with normal minutes-only mutations; no native/browser/worker/task flow",
        commands: fixture.commands,
        selector: minutesId,
        catalog,
        oneEdge: one.length,
        twoEdges: expected.length,
        scalarUtf8: scalar,
        planUnits: plan.units,
        originalCanonicalSha256: sha(canonicalJson(envelope(minutesId, expected))),
        rawTimestampChecks: observed.length,
        falseControls,
        trueConstructorFaults: 2,
        reports,
        recusalScope:
          "original endpoint A hides incoming cycle; replacement endpoint C hides outgoing cycle",
        nativeSettlement:
          "modeled markers only; actual SQL producer and allocation retention observed"
      })
    );
  });
}, 60_000);
