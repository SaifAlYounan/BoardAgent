import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  loadAdmittedVoteToolProjection,
  VOTE_TOOL_PREFLIGHT_SQL,
  VOTE_TOOL_CONTENT_SQL,
  voteToolProjectionCost,
  voteToolProjectionPlan,
  type VoteToolProjectionMetadata
} from "../../artifacts/server/src/vote-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedVoteProjectionFixture } from "../helpers/vote-projection-fixture.js";
import { seedVoteProjectionOutcome } from "../helpers/vote-projection-outcome-fixture.js";
import { ORIGINAL_VOTE_TOOL_SQL } from "../helpers/vote-tool-original-sql.js";

type ObjectValue = Readonly<Record<string, JsonValue>>;
function object(value: JsonValue | undefined): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected original vote tool object");
  return value as ObjectValue;
}
const bytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
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
function flatValues(q: ObjectValue) {
  const r = object(q["resolution"]),
    p = object(q["decision_package"]);
  const o = q["outcome"] === null ? undefined : object(q["outcome"]);
  // Independent original 10+4+11+5 flat inventory. Ballots are explicitly
  // empty in this fixture; the separate ballot case must cover their eight fields.
  return [
    q["vote_id"],
    q["board_id"],
    q["title"],
    q["state"],
    q["close_mode"],
    q["deadline_at"],
    q["row_version"],
    q["created_at"],
    q["opened_at"],
    q["closed_at"],
    r["version_id"],
    r["version"],
    r["canonical_text"],
    r["sha256"],
    p["package_id"],
    p["version"],
    p["schema_version"],
    p["package_sha256"],
    p["governance_profile_id"],
    p["governance_profile_sha256"],
    p["ruleset_id"],
    p["ruleset_sha256"],
    p["approval_rule_id"],
    p["approval_rule_sha256"],
    p["electorate_sha256"],
    o?.["outcome_id"] ?? null,
    o?.["tally_sha256"] ?? null,
    o?.["outcome"] ?? null,
    o?.["finalized_at"] ?? null,
    o?.["certificate_id"] ?? null
  ];
}
function envelope(view: JsonValue | null, voteId: string, boardId: string) {
  return {
    schema_version: "boardagent.tool-result.v1",
    tool: "get_vote",
    status: "ok",
    reference: voteId,
    resource_uri: view === null ? null : `board://${boardId}/votes/${voteId}`,
    data: { vote: view }
  };
}

it("admits original get_vote package and outcome bytes under actual server RLS with fresh global gates", async () => {
  await withMigratedDatabase("vote_tool", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      scopes: ["governance:read"]
    });
    const fixture = await seedVoteProjectionFixture(pool, actor),
      voteId = fixture.voteId;
    const manager = new ResponseAllocationManager();
    await pool.query(`create function vote_tool_root_fault() returns uuid language plpgsql volatile as $$
      begin raise exception 'vote tool root construction fault'; end $$`);
    const schema = await pool.query<{
      unique_outcome: boolean;
      secured_tables: string;
      id_primary_keys: string;
      pg_version: string;
    }>(
      `select exists(select 1 from pg_constraint as c join pg_attribute as a
         on a.attrelid=c.conrelid and a.attname='vote_id'
         where c.conrelid='vote_outcomes'::regclass and c.contype='u' and c.convalidated
         and c.conkey=array[a.attnum]::smallint[]) as unique_outcome,
       (select count(*)::text from pg_class where oid=any(array['votes'::regclass,'resolution_versions'::regclass,
         'decision_packages'::regclass,'ballots'::regclass,'vote_outcomes'::regclass])
         and relrowsecurity and relforcerowsecurity) as secured_tables,
       (select count(*)::text from pg_constraint as c join pg_attribute as a
         on a.attrelid=c.conrelid and a.attname='id'
         where c.conrelid=any(array['votes'::regclass,'resolution_versions'::regclass,
           'decision_packages'::regclass,'ballots'::regclass,'vote_outcomes'::regclass])
           and c.contype='p' and c.convalidated and c.conkey=array[a.attnum]::smallint[]) as id_primary_keys,
       current_setting('server_version_num') as pg_version`
    );
    expect(schema.rows).toEqual([
      { unique_outcome: true, secured_tables: "5", id_primary_keys: "5", pg_version: "180006" }
    ]);
    let metadataCalls = 0,
      contentCalls = 0,
      constructedRows = 0,
      sequence = 0;
    interface Options {
      voteId?: string;
      afterPreflight?: (metadata: VoteToolProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      falseParameter?: number;
      fault?: boolean;
      abortAfterMetadata?: boolean;
    }
    async function read(options: Options = {}) {
      const abort = new AbortController(),
        owner = manager.openRequest(abort.signal);
      const initial = manager.accounting.usedUnits;
      let charge: number | undefined;
      try {
        return await withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            const role = await client.query<{
              role: string;
              row_security: string;
              isolation: string;
            }>(
              "select current_user as role,current_setting('row_security') as row_security,current_setting('transaction_isolation') as isolation"
            );
            expect(role.rows).toEqual([
              { role: "boardagent_server", row_security: "on", isolation: "read committed" }
            ]);
            if (options.mode) await client.query(`set local plan_cache_mode = ${options.mode}`);
            let latest: VoteToolProjectionMetadata | undefined;
            const proxy = new Proxy(client, {
              get(target, key) {
                if (key !== "query") return Reflect.get(target, key, target);
                return async (sql: string, values?: unknown[]) => {
                  if (sql === VOTE_TOOL_CONTENT_SQL) {
                    contentCalls += 1;
                    charge = voteToolProjectionPlan(latest!).units;
                    expect(manager.accounting.usedUnits).toBe(initial + charge);
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      const needle = "'vote_id',vote.vote_id";
                      expect(text.split(needle)).toHaveLength(2);
                      text = text.replace(needle, "'vote_id',vote_tool_root_fault()");
                    }
                    if (options.falseParameter !== undefined) {
                      parameters = [...(values ?? [])];
                      parameters[options.falseParameter] =
                        options.falseParameter === 2
                          ? testId(249999)
                          : options.falseParameter === 3
                            ? "0".repeat(64)
                            : options.falseParameter <= 6
                              ? "999999"
                              : "0";
                    }
                    const result = options.mode
                      ? await target.query({
                          name: `vote-tool-${String(sequence++)}`,
                          text,
                          ...(parameters === undefined ? {} : { values: parameters })
                        })
                      : await target.query(text, parameters);
                    if (options.falseParameter !== undefined) {
                      expect(result.rows).toHaveLength(1);
                      expect(result.rows[0]).toMatchObject({ fits: false, view: null });
                    }
                    constructedRows += result.rows.filter(
                      (row: { view: unknown }) => row.view !== null
                    ).length;
                    return result;
                  }
                  const result = await target.query(sql, values);
                  if (sql === VOTE_TOOL_PREFLIGHT_SQL) {
                    metadataCalls += 1;
                    latest = result.rows[0] as VoteToolProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                    if (options.abortAfterMetadata) abort.abort();
                  }
                  return result;
                };
              }
            }) as PoolClient;
            const rows = await owner.produce(() =>
              loadAdmittedVoteToolProjection(proxy, options.voteId ?? voteId, actor.memberId)
            );
            if (charge !== undefined) expect(manager.accounting.usedUnits).toBe(initial + charge);
            return rows.map((row) => ({ view: row.view }));
          },
          { assumeRole: "boardagent_server" }
        );
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        expect(manager.accounting.usedUnits).toBe(initial);
      }
    }
    async function original() {
      return withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const found = await client.query<{ view: JsonValue }>(ORIGINAL_VOTE_TOOL_SQL, [
            voteId,
            actor.memberId
          ]);
          return found.rows;
        },
        { assumeRole: "boardagent_server" }
      );
    }
    async function verifyOracle() {
      // Deliberately materialize only synthetic original data before occupancy.
      const originalRows = await original(),
        admitted = await read();
      expect(originalRows).toHaveLength(1);
      expect(admitted).toEqual(originalRows);
      expect(bytes(admitted)).toEqual(bytes(originalRows));
      const q = object(originalRows[0]!.view),
        r = object(q["resolution"]),
        p = object(q["decision_package"]);
      expect(Object.keys(q)).toHaveLength(14);
      expect(Object.keys(r)).toHaveLength(4);
      expect(Object.keys(p)).toHaveLength(12);
      expect(q["my_ballots"]).toEqual([]);
      if (q["outcome"] !== null) expect(Object.keys(object(q["outcome"]))).toHaveLength(6);
      expect(bytes(envelope(admitted[0]!.view, voteId, actor.boardId))).toEqual(
        bytes(envelope(originalRows[0]!.view, voteId, actor.boardId))
      );
      const observed = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const raw = await client.query<{
            payload: Buffer;
            payload_json: string;
            tally_json: string | null;
            resolution_id: string;
            package_id: string;
          }>(
            `select package.canonical_payload as payload,(convert_from(package.canonical_payload,'UTF8')::jsonb)::text as payload_json,
            outcome.canonical_tally::text as tally_json,vote.current_resolution_version_id as resolution_id,vote.current_decision_package_id as package_id
           from votes as vote left join decision_packages as package on package.id=vote.current_decision_package_id
           left join vote_outcomes as outcome on outcome.vote_id=vote.id
           where vote.id=$1 and not boardagent_member_vote_recused(vote.id,$2)`,
            [voteId, actor.memberId]
          );
          const metadata = await client.query<VoteToolProjectionMetadata>(VOTE_TOOL_PREFLIGHT_SQL, [
            voteId,
            actor.memberId
          ]);
          expect(raw.rows).toHaveLength(1);
          expect(metadata.rows).toHaveLength(1);
          return { raw: raw.rows[0]!, metadata: metadata.rows[0]! };
        },
        { assumeRole: "boardagent_server" }
      );
      const flat = flatValues(q),
        graphs = [observed.raw.payload_json, observed.raw.tally_json].filter(
          (v): v is string => v !== null
        );
      const counts = graphs.map((text) => shape(JSON.parse(text)));
      expect(observed.metadata.row_count).toBe("1");
      expect(observed.metadata.ballot_count).toBe("0");
      expect(observed.metadata.outcome_count).toBe(q["outcome"] === null ? "0" : "1");
      expect(observed.metadata.scalar_utf8).toBe(
        String(
          flat.reduce<number>(
            (sum, value) => sum + (value === null ? 0 : Buffer.byteLength(String(value))),
            0
          )
        )
      );
      expect(observed.metadata.json_utf8).toBe(
        String(graphs.reduce((sum, text) => sum + Buffer.byteLength(text), 0))
      );
      expect(observed.metadata.json_properties).toBe(
        String(counts.reduce((sum, count) => sum + count.properties, 0))
      );
      expect(observed.metadata.json_containers).toBe(
        String(counts.reduce((sum, count) => sum + count.containers, 0))
      );
      expect(digest(observed.raw.payload)).toBe(p["package_sha256"]);
      // Independent private observation oracle enumerates all flat original
      // values, replacing resolution text with its actual hash, then binds raw
      // bytes, child pointers and actual PG tally spelling. No helper field map.
      const tuple = [...flat];
      tuple[12] = r["canonical_text"] === null ? null : digest(String(r["canonical_text"]));
      tuple.push(
        observed.raw.resolution_id,
        observed.raw.package_id,
        observed.raw.payload.length,
        digest(observed.raw.payload),
        observed.raw.tally_json === null ? null : digest(observed.raw.tally_json)
      );
      const privateHash = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const row = await client.query<{ sha: string }>(
            "select encode(sha256(convert_to(($1::jsonb)::text,'UTF8')),'hex') as sha",
            [JSON.stringify(tuple)]
          );
          const observation = await client.query<{ sha: string }>(
            "select encode(sha256(convert_to(($1::jsonb)::text,'UTF8')),'hex') as sha",
            [JSON.stringify([voteId, actor.memberId, row.rows[0]!.sha, digest("")])]
          );
          return observation.rows[0]!.sha;
        },
        { assumeRole: "boardagent_server" }
      );
      expect(observed.metadata.observation_sha256).toBe(privateHash);
      const cost = voteToolProjectionCost(observed.metadata),
        viewShape = shape(q);
      expect(bytes(q).length).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
      expect(viewShape.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
      expect(viewShape.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
      const result = envelope(q, voteId, actor.boardId),
        wire = {
          content: [{ type: "text", text: JSON.stringify(result) }],
          structuredContent: result
        };
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(
        voteToolProjectionPlan(observed.metadata).wireUpperBytes
      );
      return { q, ...observed };
    }
    const draft = await verifyOracle();
    expect(draft.q["outcome"]).toBeNull();
    const missingContent = contentCalls;
    expect(await read({ voteId: testId(249999) })).toEqual([]);
    expect(contentCalls).toBe(missingContent);
    const held = Array.from({ length: 2048 }, () =>
      manager.tryReserve(
        responseAllocationPlan({
          kind: "document",
          representation: "resource",
          sourceId: "small",
          sourceVersion: "1",
          sha256: "a".repeat(64),
          canonicalBytes: 1
        })
      )
    );
    const beforeMetadata = metadataCalls,
      beforeContent = contentCalls;
    try {
      await expect(read()).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(metadataCalls - beforeMetadata).toBe(1);
      expect(contentCalls - beforeContent).toBe(0);
    } finally {
      for (const lease of held) lease.release();
    }
    const abortContent = contentCalls;
    await expect(read({ abortAfterMetadata: true })).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(contentCalls).toBe(abortContent);
    // A normal mutable draft title edit increments row_version. This is actual
    // fresh-binding refusal, not an immutable same-cost text mutation claim.
    await expect(
      read({
        afterPreflight: async () => {
          const changed = await pool.query(
            "update votes set title=title || ' Δ',row_version=row_version+1 where id=$1 and state='draft' returning id",
            [voteId]
          );
          expect(changed.rowCount).toBe(1);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    await verifyOracle();
    const tallyText =
      '{"wide":1e40,"tiny":1e-40,"nested":[{},[],{"text":"Δ🙂\\n\\\"\\\\","null":null,"flag":false}]}';
    await expect(
      read({
        afterPreflight: async (metadata) => {
          expect(metadata.outcome_count).toBe("0");
          await seedVoteProjectionOutcome(pool, actor, voteId, tallyText);
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    // The normal fixture also moves draft→open→closing and increments root
    // version. Do not call this unchanged-parent outcome-growth coverage.
    const finalized = await verifyOracle();
    expect(finalized.raw.tally_json).toContain("10000000000000000000000000000000000000000");
    expect(Buffer.byteLength(finalized.raw.tally_json!)).not.toBe(
      Buffer.byteLength(JSON.stringify(JSON.parse(finalized.raw.tally_json!)))
    );
    for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
      for (const falseParameter of [2, 3, 4, 5, 6, 7, 8, 9, 10]) {
        const count = constructedRows;
        await expect(read({ mode, fault: true, falseParameter })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(constructedRows).toBe(count);
        expect(manager.accounting.usedUnits).toBe(0);
      }
      await expect(read({ mode, fault: true })).rejects.toThrow(
        "vote tool root construction fault"
      );
    }
    expect(
      await read({
        afterPreflight: async () => {
          await fixture.exclude();
        }
      })
    ).toEqual([]);
    expect(await original()).toEqual([]);
    const recusedContent = contentCalls;
    expect(await read()).toEqual([]);
    expect(contentCalls).toBe(recusedContent);
    expect(manager.accounting.usedUnits).toBe(0);
  });
});
