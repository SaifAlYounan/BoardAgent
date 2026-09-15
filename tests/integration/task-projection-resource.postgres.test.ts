import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  loadAdmittedTaskProjection,
  TASK_PROJECTION_PREFLIGHT_SQL,
  TASK_PROJECTION_CONTENT_SQL,
  taskProjectionCost,
  taskProjectionPlan,
  type TaskProjectionMetadata
} from "../../artifacts/server/src/task-projection-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import { seedTaskProjectionFixture } from "../helpers/task-projection-fixture.js";
import { ORIGINAL_TASK_RESOURCE_SQL } from "../helpers/task-resource-original-sql.js";

type ObjectValue = Readonly<Record<string, JsonValue>>;
function object(value: JsonValue | undefined): ObjectValue {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected fixture object");
  return value as ObjectValue;
}
function shape(value: unknown) {
  const stack: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (stack.length) {
    const item = stack.pop();
    if (item && typeof item === "object") {
      containers += 1;
      if (!Array.isArray(item)) properties += Object.keys(item).length;
      for (const child of Object.values(item)) stack.push(child);
    }
  }
  return { properties, containers };
}
// Independent original 13 + 4 per evidence + 2 closure flat inventory.
function flatBytes(q: ObjectValue) {
  const values: unknown[] = [
    q["schema_version"],
    q["task_id"],
    q["board_id"],
    q["source_minutes_id"],
    q["source_minutes_version_id"],
    q["source_minutes_sha256"],
    q["owner_member_id"],
    q["due_at"],
    q["description_schema"],
    q["canonical_description"],
    q["task_sha256"],
    q["state"],
    q["row_version"]
  ];
  for (const item of q["evidence"] as readonly JsonValue[]) {
    const evidence = object(item);
    values.push(
      evidence["evidence_id"],
      evidence["canonical_text"],
      evidence["sha256"],
      evidence["state"]
    );
  }
  if (q["closure"] !== null) {
    const closure = object(q["closure"]);
    values.push(closure["closure_id"], closure["closure_sha256"]);
  }
  return values.reduce<number>(
    (sum, value) => sum + (value === null ? 0 : Buffer.byteLength(String(value))),
    0
  );
}
const bytes = (value: JsonValue) => Buffer.from(canonicalJson(value), "utf8");

it("admits the original task and action-item resources and gates fresh projection under the actual server role", async () => {
  await withMigratedDatabase("task_projection", async (pool) => {
    const f = await seedTaskProjectionFixture(pool),
      actor = f.actor;
    await pool.query(`create function task_projection_fault() returns uuid language plpgsql volatile as $$
      begin raise exception 'task projection construction fault'; end $$`);
    interface Options {
      boardId?: string;
      taskId?: string;
      actionOnly?: boolean;
      afterPreflight?: (metadata: TaskProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      fault?: boolean;
      reducedParameter?: number;
    }
    const manager = new ResponseAllocationManager();
    let latest: TaskProjectionMetadata | undefined;
    let metadataCalls = 0,
      contentCalls = 0,
      contentRows = 0,
      sequence = 0;
    async function read(options: Options = {}) {
      const owner = manager.openRequest(new AbortController().signal),
        initialUnits = manager.accounting.usedUnits;
      let chargedUnits: number | undefined;
      try {
        return await withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            if (options.mode) await client.query(`set local plan_cache_mode = ${options.mode}`);
            const proxy = new Proxy(client, {
              get(target, key) {
                if (key !== "query") return Reflect.get(target, key, target);
                return async (sql: string, values?: unknown[]) => {
                  if (sql === TASK_PROJECTION_CONTENT_SQL) {
                    contentCalls += 1;
                    chargedUnits = taskProjectionPlan(latest!).units;
                    expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      const needle = "'task_id',task.id";
                      expect(text.includes(needle)).toBe(true);
                      text = text.replace(needle, "'task_id',task_projection_fault()");
                    }
                    if (options.reducedParameter !== undefined) {
                      parameters = [...(values ?? [])];
                      parameters[options.reducedParameter] =
                        options.reducedParameter === 4 ? "0".repeat(64) : "0";
                    }
                    const result = options.mode
                      ? await target.query({
                          name: `task-projection-${String(sequence++)}`,
                          text,
                          ...(parameters === undefined ? {} : { values: parameters })
                        })
                      : await target.query(text, parameters);
                    contentRows += result.rows.filter(
                      (row: { payload: unknown }) => row.payload !== null
                    ).length;
                    return result;
                  }
                  const result = await target.query(sql, values);
                  if (sql === TASK_PROJECTION_PREFLIGHT_SQL) {
                    metadataCalls += 1;
                    latest = result.rows[0] as TaskProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            const result = await owner.produce(() =>
              loadAdmittedTaskProjection(proxy, {
                boardId: options.boardId ?? actor.boardId,
                taskId: options.taskId ?? f.taskId,
                actionOnly: options.actionOnly ?? false,
                memberId: actor.memberId
              })
            );
            if (chargedUnits !== undefined)
              expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
            return result;
          },
          { assumeRole: "boardagent_server" }
        );
      } catch (error) {
        if (chargedUnits !== undefined)
          expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
        throw error;
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        expect(manager.accounting.usedUnits).toBe(initialUnits);
      }
    }
    async function original(taskId = f.taskId, actionOnly = false) {
      return withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const found = await client.query<{ id: string; row_version: string; payload: JsonValue }>(
            ORIGINAL_TASK_RESOURCE_SQL,
            [actor.boardId, taskId, actionOnly, actor.memberId]
          );
          return found.rows[0] ?? null;
        },
        { assumeRole: "boardagent_server" }
      );
    }
    // Independent original full SQL and canonical byte oracle BEFORE saturation, for
    // the task resource and the action-item resource of the same minutes-sourced task.
    for (const actionOnly of [false, true]) {
      const raw = await original(f.taskId, actionOnly),
        admitted = await read({ actionOnly });
      expect(raw).not.toBeNull();
      expect(admitted).toEqual(raw);
      expect(bytes(admitted!.payload)).toEqual(bytes(raw!.payload));
    }
    const q = object((await original())!.payload);
    expect(Object.keys(q)).toHaveLength(16);
    expect(q["evidence"]).toHaveLength(2);
    expect(Object.keys(object((q["evidence"] as JsonValue[])[0]))).toHaveLength(6);
    expect(Object.keys(object(q["closure"]))).toHaveLength(3);
    expect(object(q["closure"])["closure_id"]).toBe(f.closureId);
    // The replacement task has no minutes source: a task, never an action item.
    const replacement = await original(f.replacementId);
    expect(replacement).not.toBeNull();
    expect(await read({ taskId: f.replacementId })).toEqual(replacement);
    expect(object(replacement!.payload)["closure"]).toBeNull();
    expect(object(replacement!.payload)["evidence"]).toEqual([]);
    expect(await original(f.replacementId, true)).toBeNull();
    const beforeReplacementContent = contentCalls;
    expect(await read({ taskId: f.replacementId, actionOnly: true })).toBeNull();
    expect(contentCalls).toBe(beforeReplacementContent);

    // Measured scalars equal an independent oracle over the original payload and the
    // PostgreSQL text spelling of every JSONB value in the graph.
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const json = await client.query<{ value: string }>(
          `select required_evidence::text as value from tasks where id=$1
           union all select document_references::text from task_evidence where task_id=$1
           union all select resource_references::text from task_evidence where task_id=$1
           union all select accepted_evidence_manifest::text from task_closures where task_id=$1`,
          [f.taskId]
        );
        const measured = await client.query<TaskProjectionMetadata>(TASK_PROJECTION_PREFLIGHT_SQL, [
          actor.boardId,
          f.taskId,
          false,
          actor.memberId
        ]);
        expect(measured.rows).toHaveLength(1);
        return { json: json.rows.map((row) => row.value), metadata: measured.rows[0]! };
      },
      { assumeRole: "boardagent_server" }
    );
    expect(oracle.json).toHaveLength(6);
    expect(oracle.metadata.scalar_utf8).toBe(String(flatBytes(q)));
    expect(oracle.metadata.json_utf8).toBe(
      String(oracle.json.reduce((sum, text) => sum + Buffer.byteLength(text), 0))
    );
    const jsonShape = oracle.json
      .map((text) => shape(JSON.parse(text)))
      .reduce((sum, item) => ({
        properties: sum.properties + item.properties,
        containers: sum.containers + item.containers
      }));
    expect(oracle.metadata.json_properties).toBe(String(jsonShape.properties));
    expect(oracle.metadata.json_containers).toBe(String(jsonShape.containers));
    expect(oracle.metadata.evidence_count).toBe("2");
    expect(oracle.metadata.closure_count).toBe("1");
    expect(oracle.metadata.closure_id).toBe(f.closureId);
    expect(
      oracle.json.some((text) => text.includes("10000000000000000000000000000000000000000"))
    ).toBe(true);
    const cost = taskProjectionCost(oracle.metadata),
      actualShape = shape(q);
    expect(BigInt(bytes(q).length)).toBeLessThanOrEqual(BigInt(cost.jsonUpperBytes));
    expect(BigInt(actualShape.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(actualShape.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));

    // Evidence edits between preflight and content change the bound observation,
    // whether or not the task row itself moved; the refetch then sees the change.
    await expect(
      read({
        afterPreflight: async () => {
          const changed = await pool.query(
            "update task_evidence set state='rejected',row_version=row_version+1 where id=$1 and state='submitted'",
            [f.evidenceIds[0]]
          );
          expect(changed.rowCount).toBe(1);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const current = await read();
    expect(object((object(current!.payload)["evidence"] as JsonValue[])[0])["state"]).toBe(
      "rejected"
    );
    // A fresh evidence row is a larger graph: refused in flight, admitted on refetch.
    await expect(
      read({
        afterPreflight: async () => {
          await pool.query(
            `insert into task_evidence(id,organization_id,board_id,task_id,owner_member_id,canonical_text,
               document_references,resource_references,canonical_sha256,state)
             values ($1,$2,$3,$4,$5,'Late synthetic evidence.','[]'::jsonb,'[]'::jsonb,$6,'submitted')`,
            [
              testId(240_022),
              actor.organizationId,
              actor.boardId,
              f.taskId,
              actor.memberId,
              Buffer.alloc(32, 22)
            ]
          );
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const grown = await read(),
      grownOriginal = await original();
    expect(object(grown!.payload)["evidence"]).toHaveLength(3);
    expect(grown).toEqual(grownOriginal);
    expect(bytes(grown!.payload)).toEqual(bytes(grownOriginal!.payload));

    const previousContent = contentCalls;
    expect(await read({ boardId: testId(229_999) })).toBeNull();
    expect(contentCalls).toBe(previousContent);
    const held = Array.from({ length: 2048 }, () =>
      manager.tryReserve(
        responseAllocationPlan({
          kind: "document",
          representation: "tool",
          sourceId: "small",
          sourceVersion: "1",
          sha256: "a".repeat(64),
          canonicalBytes: 1
        })
      )
    );
    const beforeMeta = metadataCalls,
      beforeContent = contentCalls;
    try {
      await expect(read()).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(metadataCalls - beforeMeta).toBe(1);
      expect(contentCalls - beforeContent).toBe(0);
    } finally {
      for (const lease of held) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);
    for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
      // Every guarded identity/scalar is independently made wrong or too small.
      // The constructor fault must remain unreachable in the separate subquery.
      for (const reducedParameter of [4, 5, 6, 7, 8, 9, 10]) {
        const beforeRows = contentRows;
        await expect(read({ mode, fault: true, reducedParameter })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(contentRows).toBe(beforeRows);
        expect(manager.accounting.usedUnits).toBe(0);
      }
      await expect(read({ mode, fault: true })).rejects.toThrow(
        "task projection construction fault"
      );
      expect(manager.accounting.usedUnits).toBe(0);
    }
    // A meeting recusal stored after preflight hides the sourced task at content time.
    expect(
      await read({
        afterPreflight: async () => {
          await f.exclude();
        }
      })
    ).toBeNull();
    const hiddenContent = contentCalls;
    expect(await read()).toBeNull();
    expect(await original()).toBeNull();
    expect(contentCalls).toBe(hiddenContent);
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
