import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  loadAdmittedTaskToolProjection,
  TASK_TOOL_PREFLIGHT_SQL,
  TASK_TOOL_CONTENT_SQL,
  taskToolProjectionCost,
  taskToolProjectionPlan,
  type TaskToolProjectionMetadata
} from "../../artifacts/server/src/task-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  seedTaskProjectionFixture,
  seedTaskSyntheticConsent
} from "../helpers/task-projection-fixture.js";
import { ORIGINAL_TASK_TOOL_SQL } from "../helpers/task-tool-original-sql.js";

type ObjectValue = Readonly<Record<string, JsonValue>>;
function object(value: JsonValue | undefined): ObjectValue {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected original task tool object");
  return value as ObjectValue;
}
const bytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");
function shape(value: unknown) {
  const pending: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const item = pending.pop();
    if (item !== null && typeof item === "object") {
      containers += 1;
      if (!Array.isArray(item)) properties += Object.keys(item).length;
      for (const child of Object.values(item)) pending.push(child);
    }
  }
  return { properties, containers };
}
// Independent original 16 + (6 + 5 review) per evidence + 6 closure + 5 per cycle flat inventory.
function flatBytes(q: ObjectValue) {
  const values: (JsonValue | undefined)[] = [
    q["task_id"],
    q["board_id"],
    q["source_meeting_id"],
    q["source_minutes_id"],
    q["source_minutes_version_id"],
    q["source_minutes_sha256"],
    q["owner_member_id"],
    q["due_at"],
    q["description_schema"],
    q["canonical_description"],
    q["task_sha256"],
    q["state"],
    q["row_version"],
    q["created_at"],
    q["completed_at"],
    q["cancelled_at"]
  ];
  for (const item of q["evidence"] as readonly JsonValue[]) {
    const evidence = object(item);
    values.push(
      evidence["evidence_id"],
      evidence["canonical_text"],
      evidence["sha256"],
      evidence["state"],
      evidence["row_version"],
      evidence["submitted_at"]
    );
    if (evidence["review"] !== null) {
      const review = object(evidence["review"]);
      values.push(
        review["review_id"],
        review["decision"],
        review["reason"],
        review["secretary_member_id"],
        review["reviewed_at"]
      );
    }
  }
  if (q["closure"] !== null) {
    const closure = object(q["closure"]);
    values.push(
      closure["closure_id"],
      closure["primary_evidence_id"],
      closure["source_minutes_sha256"],
      closure["secretary_member_id"],
      closure["closure_sha256"],
      closure["closed_at"]
    );
  }
  for (const item of q["correction_cycles"] as readonly JsonValue[]) {
    const cycle = object(item);
    values.push(
      cycle["cycle_id"],
      cycle["prior_task_id"],
      cycle["replacement_task_id"],
      cycle["reason"],
      cycle["created_at"]
    );
  }
  return values.reduce<number>(
    (sum, value) =>
      sum + (value === null || value === undefined ? 0 : Buffer.byteLength(String(value))),
    0
  );
}

it("admits the original get_task/get_action_item graph and gates fresh projection under the actual server role", async () => {
  await withMigratedDatabase("task_tool_projection", async (pool) => {
    const f = await seedTaskProjectionFixture(pool),
      actor = f.actor;
    await pool.query(`create function task_tool_fault() returns uuid language plpgsql volatile as $$
      begin raise exception 'task tool construction fault'; end $$`);
    interface Options {
      taskId?: string;
      actionOnly?: boolean;
      afterPreflight?: (metadata: TaskToolProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      fault?: boolean;
      reducedParameter?: number;
    }
    const manager = new ResponseAllocationManager();
    let latest: TaskToolProjectionMetadata | undefined;
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
                  if (sql === TASK_TOOL_CONTENT_SQL) {
                    contentCalls += 1;
                    chargedUnits = taskToolProjectionPlan(latest!).units;
                    expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      const needle = "'task_id',task.id";
                      expect(text.includes(needle)).toBe(true);
                      text = text.replace(needle, "'task_id',task_tool_fault()");
                    }
                    if (options.reducedParameter !== undefined) {
                      parameters = [...(values ?? [])];
                      parameters[options.reducedParameter] =
                        options.reducedParameter === 3
                          ? testId(229_999)
                          : options.reducedParameter === 4
                            ? "0".repeat(64)
                            : "0";
                    }
                    const result = options.mode
                      ? await target.query({
                          name: `task-tool-${String(sequence++)}`,
                          text,
                          ...(parameters === undefined ? {} : { values: parameters })
                        })
                      : await target.query(text, parameters);
                    contentRows += result.rows.filter(
                      (row: { view: unknown }) => row.view !== null
                    ).length;
                    return result;
                  }
                  const result = await target.query(sql, values);
                  if (sql === TASK_TOOL_PREFLIGHT_SQL) {
                    metadataCalls += 1;
                    latest = result.rows[0] as TaskToolProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            const result = await owner.produce(() =>
              loadAdmittedTaskToolProjection(proxy, {
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
          const found = await client.query<{ view: JsonValue }>(ORIGINAL_TASK_TOOL_SQL, [
            taskId,
            actionOnly,
            actor.memberId
          ]);
          return found.rows[0] ?? null;
        },
        { assumeRole: "boardagent_server" }
      );
    }
    // Independent original full SQL and canonical byte oracle BEFORE saturation, for
    // get_task and get_action_item on the same minutes-sourced task.
    for (const actionOnly of [false, true]) {
      const raw = await original(f.taskId, actionOnly),
        admitted = await read({ actionOnly });
      expect(raw).not.toBeNull();
      expect(admitted).toEqual(raw);
      expect(bytes(admitted!.view)).toEqual(bytes(raw!.view));
    }
    const q = object((await original())!.view);
    expect(Object.keys(q)).toHaveLength(21);
    const evidence = q["evidence"] as JsonValue[];
    expect(evidence).toHaveLength(2);
    expect(Object.keys(object(evidence[0]))).toHaveLength(9);
    expect(object(evidence[0])["review"]).toBeNull();
    expect(Object.keys(object(object(evidence[1])["review"]))).toHaveLength(5);
    expect(object(object(evidence[1])["review"])["review_id"]).toBe(f.reviewId);
    expect(Object.keys(object(q["closure"]))).toHaveLength(7);
    expect(q["correction_cycles"]).toHaveLength(1);
    expect(Object.keys(object((q["correction_cycles"] as JsonValue[])[0]))).toHaveLength(5);
    expect(q["completed_at"]).not.toBeNull();
    expect(q["cancelled_at"]).toBeNull();
    // The replacement task carries the same cycle from its side and no minutes source.
    const replacement = await original(f.replacementId);
    expect(replacement).not.toBeNull();
    expect(await read({ taskId: f.replacementId })).toEqual(replacement);
    expect(object(replacement!.view)["correction_cycles"]).toHaveLength(1);
    expect(object(replacement!.view)["closure"]).toBeNull();
    expect(await original(f.replacementId, true)).toBeNull();
    const beforeReplacementContent = contentCalls;
    expect(await read({ taskId: f.replacementId, actionOnly: true })).toBeNull();
    expect(contentCalls).toBe(beforeReplacementContent);

    // Measured scalars equal an independent oracle over the original view and the
    // PostgreSQL text spelling of every JSONB value in the graph.
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const json = await client.query<{ value: string }>(
          `select source_locator::text as value from tasks where id=$1 and source_locator is not null
           union all select required_evidence::text from tasks where id=$1
           union all select document_references::text from task_evidence where task_id=$1
           union all select resource_references::text from task_evidence where task_id=$1
           union all select accepted_evidence_manifest::text from task_closures where task_id=$1`,
          [f.taskId]
        );
        const measured = await client.query<TaskToolProjectionMetadata>(TASK_TOOL_PREFLIGHT_SQL, [
          f.taskId,
          false,
          actor.memberId
        ]);
        expect(measured.rows).toHaveLength(1);
        return { json: json.rows.map((row) => row.value), metadata: measured.rows[0]! };
      },
      { assumeRole: "boardagent_server" }
    );
    expect(oracle.json).toHaveLength(7);
    expect(oracle.metadata).toMatchObject({
      task_id: f.taskId,
      board_id: actor.boardId,
      member_id: actor.memberId,
      row_version: q["row_version"],
      evidence_count: "2",
      review_count: "1",
      closure_count: "1",
      cycle_count: "1"
    });
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
    const cost = taskToolProjectionCost(oracle.metadata),
      actualShape = shape(q);
    expect(BigInt(bytes(q).length)).toBeLessThanOrEqual(BigInt(cost.jsonUpperBytes));
    expect(BigInt(actualShape.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(actualShape.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));

    // A review stored between preflight and content changes the bound observation
    // without touching the task row; the refetch then carries it.
    await expect(
      read({
        afterPreflight: async () => {
          const late = await seedTaskSyntheticConsent(pool, actor, {
            id: f.taskId,
            type: "task",
            actionCode: "review_task_evidence",
            idBase: 240_150
          });
          await pool.query(
            `insert into task_evidence_reviews(id,organization_id,evidence_id,secretary_member_id,decision,reason,consent_record_id)
             values ($1,$2,$3,$4,'rejected','Synthetic late rejection.',$5)`,
            [testId(240_032), actor.organizationId, f.evidenceIds[0], actor.memberId, late.consent]
          );
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const reviewed = await read(),
      reviewedOriginal = await original();
    expect(reviewed).toEqual(reviewedOriginal);
    expect(
      object(object((object(reviewed!.view)["evidence"] as JsonValue[])[0])["review"])["decision"]
    ).toBe("rejected");

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
      // Every guarded identity/count/scalar is independently made wrong or too small.
      // The constructor fault must remain unreachable in the separate subquery.
      for (const reducedParameter of [3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) {
        const beforeRows = contentRows;
        await expect(read({ mode, fault: true, reducedParameter })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(contentRows).toBe(beforeRows);
        expect(manager.accounting.usedUnits).toBe(0);
      }
      await expect(read({ mode, fault: true })).rejects.toThrow("task tool construction fault");
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
