import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/index.js";
import {
  loadAdmittedVoteProjection,
  VOTE_PROJECTION_PREFLIGHT_SQL,
  VOTE_PROJECTION_CONTENT_SQL,
  voteProjectionCost,
  voteProjectionPlan,
  type VoteProjectionMetadata
} from "../../artifacts/server/src/vote-projection-resource.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedVoteProjectionFixture } from "../helpers/vote-projection-fixture.js";
import { seedVoteProjectionOutcome } from "../helpers/vote-projection-outcome-fixture.js";
import { ORIGINAL_VOTE_RESOURCE_SQL } from "../helpers/vote-resource-original-sql.js";

type ObjectValue = Readonly<Record<string, JsonValue>>;
function object(value: JsonValue): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value))
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
function flatBytes(q: ObjectValue) {
  const values: unknown[] = [
    q["schema_version"],
    q["vote_id"],
    q["board_id"],
    q["title"],
    q["state"],
    q["resolution_version_id"],
    q["decision_package_id"],
    q["approval_rule_id"],
    q["governance_profile_id"],
    q["ruleset_id"],
    q["electorate_sha256"],
    q["close_mode"],
    q["deadline_at"],
    q["row_version"]
  ];
  if (q["outcome"] !== null) {
    const outcome = object(q["outcome"]!);
    values.push(
      outcome["outcome_id"],
      outcome["tally_sha256"],
      outcome["outcome"],
      outcome["certificate_id"]
    );
  }
  return values.reduce<number>(
    (sum, value) => sum + (value === null ? 0 : Buffer.byteLength(String(value))),
    0
  );
}
const bytes = (value: JsonValue) => Buffer.from(canonicalJson(value), "utf8");

it("admits the original vote resource and gates fresh projection under the actual server role", async () => {
  await withMigratedDatabase("vote_projection", async (pool) => {
    // Standalone constrained vote/package fixture; no linked Q&A cutoff or
    // public vote-open/close ceremony is represented by these storage rows.
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["governance:read"]
    });
    const link = await seedVoteProjectionFixture(pool, actor),
      voteId = link.voteId;
    await pool.query(`create function vote_projection_fault() returns uuid language plpgsql volatile as $$
      begin raise exception 'vote projection construction fault'; end $$`);
    interface Options {
      boardId?: string;
      afterPreflight?: (metadata: VoteProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      fault?: boolean;
      reducedParameter?: number;
    }
    const manager = new ResponseAllocationManager();
    let latest: VoteProjectionMetadata | undefined;
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
                  if (sql === VOTE_PROJECTION_CONTENT_SQL) {
                    contentCalls += 1;
                    chargedUnits = voteProjectionPlan(latest!).units;
                    expect(manager.accounting.usedUnits).toBe(initialUnits + chargedUnits);
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      const needle = "'vote_id',vote.id";
                      expect(text.includes(needle)).toBe(true);
                      text = text.replace(needle, "'vote_id',vote_projection_fault()");
                    }
                    if (options.reducedParameter !== undefined) {
                      parameters = [...(values ?? [])];
                      parameters[options.reducedParameter] =
                        options.reducedParameter === 3 ? testId(229999) : "0";
                    }
                    const result = options.mode
                      ? await target.query({
                          name: `vote-projection-${String(sequence++)}`,
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
                  if (sql === VOTE_PROJECTION_PREFLIGHT_SQL) {
                    metadataCalls += 1;
                    latest = result.rows[0] as VoteProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                  }
                  return result;
                };
              }
            }) as PoolClient;
            const result = await owner.produce(() =>
              loadAdmittedVoteProjection(proxy, options.boardId ?? actor.boardId, voteId)
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
    async function original() {
      return withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const found = await client.query<{ id: string; row_version: string; payload: JsonValue }>(
            ORIGINAL_VOTE_RESOURCE_SQL,
            [actor.boardId, voteId]
          );
          expect(found.rows).toHaveLength(1);
          return found.rows[0]!;
        },
        { assumeRole: "boardagent_server" }
      );
    }
    // Independent original full SQL and canonical byte oracle BEFORE saturation.
    const draft = await original(),
      admittedDraft = await read();
    expect(admittedDraft).toEqual(draft);
    expect(bytes(admittedDraft!.payload)).toEqual(bytes(draft.payload));
    expect(object(draft.payload)["outcome"]).toBeNull();
    // Existing vote edits always increment row_version. Even equal-width title
    // changes therefore refuse this in-flight observation, then work on refetch.
    // The separate custom/generic reduced-bound controls isolate scalar gates.
    for (const title of ["Synthetic decision resourcE", "Synthetic decision resourcE Δ"]) {
      await expect(
        read({
          afterPreflight: async (metadata) => {
            const changed = await pool.query<{ row_version: string }>(
              `update votes set title=$2,row_version=row_version+1
           where id=$1 and state='draft' and row_version=$3::bigint returning row_version::text`,
              [voteId, title, metadata.row_version]
            );
            expect(changed.rowCount).toBe(1);
            expect(BigInt(changed.rows[0]!.row_version)).toBe(BigInt(metadata.row_version) + 1n);
          }
        })
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      const current = await read();
      expect(object(current!.payload)["title"]).toBe(title);
    }
    await expect(
      read({
        afterPreflight: async (metadata) => {
          const changed = await pool.query<{ row_version: string }>(
            `update votes set row_version=row_version+1
        where id=$1 and state='draft' and row_version=$2::bigint returning row_version::text`,
            [voteId, metadata.row_version]
          );
          expect(changed.rowCount).toBe(1);
          expect(changed.rows[0]!.row_version.length).toBe(metadata.row_version.length);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    // Canonical tally is immutable after insertion. The storage fixture admits
    // JSONB numeric spelling/graph samples without running tally recomputation.
    const tallyText =
      '{"wide":1e40,"tiny":1e-40,"nested":[{},[],{"text":"Δ🙂\\n\\\"\\\\","null":null,"flag":false}]}';
    let outcome: Awaited<ReturnType<typeof seedVoteProjectionOutcome>> | undefined;
    await expect(
      read({
        afterPreflight: async (metadata) => {
          expect(metadata.outcome_id).toBeNull();
          expect(metadata.outcome_count).toBe("0");
          outcome = await seedVoteProjectionOutcome(pool, actor, voteId, tallyText);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const raw = await original(),
      admitted = await read();
    expect(admitted).toEqual(raw);
    expect(bytes(admitted!.payload)).toEqual(bytes(raw.payload));
    const q = object(raw.payload),
      selected = object(q["outcome"]!);
    expect(Object.keys(q)).toHaveLength(15);
    expect(Object.keys(selected)).toHaveLength(5);
    expect(selected["outcome_id"]).toBe(outcome!.outcomeId);
    expect(selected["certificate_id"]).toBe(outcome!.certificateId);
    expect(selected["tally_sha256"]).toBe(outcome!.tallyHash.toString("hex"));
    const oracle = await withRequestTransaction(
      pool,
      actor.context,
      async (client) => {
        const originalTally = await client.query<{ value: string }>(
          `select canonical_tally::text as value
        from vote_outcomes where vote_id=$1 and id=$2`,
          [voteId, outcome!.outcomeId]
        );
        expect(originalTally.rows).toHaveLength(1);
        const measured = await client.query<VoteProjectionMetadata>(VOTE_PROJECTION_PREFLIGHT_SQL, [
          actor.boardId,
          voteId
        ]);
        expect(measured.rows).toHaveLength(1);
        return { tally: originalTally.rows[0]!.value, metadata: measured.rows[0]! };
      },
      { assumeRole: "boardagent_server" }
    );
    expect(oracle.metadata.scalar_utf8).toBe(String(flatBytes(q)));
    expect(oracle.metadata.json_utf8).toBe(String(Buffer.byteLength(oracle.tally)));
    const tallyShape = shape(JSON.parse(oracle.tally));
    expect(oracle.metadata.json_properties).toBe(String(tallyShape.properties));
    expect(oracle.metadata.json_containers).toBe(String(tallyShape.containers));
    expect(oracle.metadata.outcome_count).toBe("1");
    expect(oracle.metadata.outcome_id).toBe(outcome!.outcomeId);
    expect(oracle.tally.includes("10000000000000000000000000000000000000000")).toBe(true);
    expect(Buffer.byteLength(oracle.tally)).not.toBe(
      Buffer.byteLength(JSON.stringify(JSON.parse(oracle.tally)))
    );
    const cost = voteProjectionCost(oracle.metadata),
      actualShape = shape(q);
    expect(BigInt(bytes(q).length)).toBeLessThanOrEqual(BigInt(cost.jsonUpperBytes));
    expect(BigInt(actualShape.properties)).toBeLessThanOrEqual(BigInt(cost.propertyCount));
    expect(BigInt(actualShape.containers)).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
    const previousContent = contentCalls;
    expect(await read({ boardId: testId(229999) })).toBeNull();
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
      // Every guarded identity/scalar is independently made too small/wrong.
      // The constructor fault must remain unreachable in the separate subquery.
      for (const reducedParameter of [2, 3, 4, 5, 6, 7, 8]) {
        const beforeRows = contentRows;
        await expect(read({ mode, fault: true, reducedParameter })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(contentRows).toBe(beforeRows);
        expect(manager.accounting.usedUnits).toBe(0);
      }
      await expect(read({ mode, fault: true })).rejects.toThrow(
        "vote projection construction fault"
      );
      expect(manager.accounting.usedUnits).toBe(0);
    }
    // Existing vote-recusal semantics are checked directly. Unlike question
    // visibility's time window, do not assume a new timing rule for this helper.
    expect(
      await read({
        afterPreflight: async () => {
          await link.exclude();
        }
      })
    ).toBeNull();
    const hiddenContent = contentCalls;
    expect(await read()).toBeNull();
    expect(contentCalls).toBe(hiddenContent);
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
