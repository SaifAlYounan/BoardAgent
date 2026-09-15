import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  castBallotInTransaction,
  grantProxyInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
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
  ResponseAllocationUnavailable
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  seedVoteToolBallotFixture,
  confirmedVoteToolProxyGrantInput,
  confirmedVoteToolBallotInput,
  type VoteToolBallotFixture
} from "../helpers/vote-tool-ballot-fixture.js";
import { ORIGINAL_VOTE_TOOL_SQL } from "../helpers/vote-tool-original-sql.js";

type Actor = VoteToolBallotFixture["actorA"];
type ObjectValue = Readonly<Record<string, JsonValue>>;
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const bytes = (value: unknown) => Buffer.from(canonicalJson(value), "utf8");
function object(value: JsonValue | undefined): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected vote object");
  return value as ObjectValue;
}
function shape(value: unknown) {
  const pending: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const node = pending.pop();
    if (node !== null && typeof node === "object") {
      containers += 1;
      if (!Array.isArray(node)) properties += Object.keys(node).length;
      for (const child of Object.values(node)) pending.push(child);
    }
  }
  return { properties, containers };
}
function flatRoot(q: ObjectValue) {
  const r = object(q["resolution"]),
    p = object(q["decision_package"]);
  expect(q["outcome"]).toBeNull();
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
    null,
    null,
    null,
    null,
    null
  ];
}
function flatBallot(b: ObjectValue) {
  return [
    b["ballot_id"],
    b["principal_member_id"],
    b["caster_member_id"],
    b["choice"],
    b["statement"],
    b["voting_weight"],
    b["source"],
    b["cast_at"]
  ];
}

it("preserves actual principal and caster ballots and skips nested aggregate values under false vote tool gates", async () => {
  await withMigratedDatabase("vote_tool_ballots", async (pool) => {
    const fixture = await seedVoteToolBallotFixture(pool),
      { actorA, actorB, voteId } = fixture;
    const grant = await confirmedVoteToolProxyGrantInput(pool, fixture, {
      actor: actorB,
      holderMemberId: actorA.memberId,
      idBase: 250000
    });
    await withRequestTransaction(
      pool,
      actorB.context,
      (client) => grantProxyInTransaction(client, grant),
      { assumeRole: "boardagent_server" }
    );
    const proxy = await confirmedVoteToolBallotInput(pool, fixture, {
      actor: actorA,
      principalMemberId: actorB.memberId,
      proxyGrantId: grant.proxyGrantId,
      choice: "yes",
      statement: "Synthetic proxy Δ 🙂",
      idBase: 250200
    });
    const ownA = await confirmedVoteToolBallotInput(pool, fixture, {
      actor: actorA,
      principalMemberId: actorA.memberId,
      choice: "no",
      statement: "Synthetic own A\n",
      idBase: 250100
    });
    // Cast the higher ID first: a real cast_at tie must then sort by ID,
    // observably differently from insertion order. No stored time is edited.
    // Normal action functions run sequentially in one actual request transaction.
    // If cast_at uses transaction time, the independent timestamp/ID oracle below
    // also exercises the tie case; record the actual timestamps instead of forcing them.
    await withRequestTransaction(
      pool,
      actorA.context,
      async (client) => {
        await castBallotInTransaction(client, proxy);
        await castBallotInTransaction(client, ownA);
      },
      { assumeRole: "boardagent_server" }
    );
    const ownB = await confirmedVoteToolBallotInput(pool, fixture, {
      actor: actorB,
      principalMemberId: actorB.memberId,
      choice: "no",
      statement: "Synthetic own B",
      idBase: 250300
    });
    await pool.query(`create function vote_tool_ballot_value_fault(value uuid) returns uuid language plpgsql volatile as $$
      begin raise exception 'vote tool nested ballot value fault'; end $$`);
    const manager = new ResponseAllocationManager();
    let sequence = 0,
      contentCalls = 0,
      constructedRows = 0;
    interface Options {
      afterPreflight?: (metadata: VoteToolProjectionMetadata) => Promise<void>;
      mode?: "force_custom_plan" | "force_generic_plan";
      falseParameter?: number;
      fault?: boolean;
    }
    async function read(actor: Actor, options: Options = {}) {
      const owner = manager.openRequest(new AbortController().signal);
      try {
        return await withRequestTransaction(
          pool,
          actor.context,
          async (client) => {
            const role = await client.query<{ role: string; row_security: string }>(
              "select current_user as role,current_setting('row_security') as row_security"
            );
            expect(role.rows).toEqual([{ role: "boardagent_server", row_security: "on" }]);
            if (options.mode) await client.query(`set local plan_cache_mode = ${options.mode}`);
            let latest: VoteToolProjectionMetadata | undefined;
            const connection = new Proxy(client, {
              get(target, key) {
                if (key !== "query") return Reflect.get(target, key, target);
                return async (sql: string, values?: unknown[]) => {
                  if (sql === VOTE_TOOL_CONTENT_SQL) {
                    contentCalls += 1;
                    expect(manager.accounting.usedUnits).toBe(
                      voteToolProjectionPlan(latest!).units
                    );
                    let text = sql,
                      parameters = values;
                    if (options.fault) {
                      // A real entitled ballot must exist. Inject inside the value
                      // passed to nested jsonb_agg's jsonb_build_object argument.
                      expect(BigInt(latest!.ballot_count)).toBeGreaterThan(0n);
                      const needle = "'ballot_id',ballot.id";
                      expect(text.split(needle)).toHaveLength(2);
                      text = text.replace(
                        needle,
                        "'ballot_id',vote_tool_ballot_value_fault(ballot.id)"
                      );
                    }
                    if (options.falseParameter !== undefined) {
                      parameters = [...(values ?? [])];
                      parameters[options.falseParameter] =
                        options.falseParameter === 2
                          ? testId(259999)
                          : options.falseParameter === 3
                            ? "0".repeat(64)
                            : options.falseParameter <= 6
                              ? "999999"
                              : "0";
                    }
                    const found = options.mode
                      ? await target.query({
                          name: `vote-ballot-${String(sequence++)}`,
                          text,
                          ...(parameters === undefined ? {} : { values: parameters })
                        })
                      : await target.query(text, parameters);
                    if (options.falseParameter !== undefined) {
                      expect(found.rows).toHaveLength(1);
                      expect(found.rows[0]).toMatchObject({ fits: false, view: null });
                    }
                    constructedRows += found.rows.filter(
                      (row: { view: unknown }) => row.view !== null
                    ).length;
                    return found;
                  }
                  const found = await target.query(sql, values);
                  if (sql === VOTE_TOOL_PREFLIGHT_SQL) {
                    latest = found.rows[0] as VoteToolProjectionMetadata | undefined;
                    if (latest) await options.afterPreflight?.(latest);
                  }
                  return found;
                };
              }
            }) as PoolClient;
            const rows = await owner.produce(() =>
              loadAdmittedVoteToolProjection(connection, voteId, actor.memberId)
            );
            expect(rows).toHaveLength(1);
            return rows.map((row) => ({ view: row.view }));
          },
          { assumeRole: "boardagent_server" }
        );
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
        expect(manager.accounting.usedUnits).toBe(0);
      }
    }
    async function verify(actor: Actor, allIds: readonly string[], selectedIds: readonly string[]) {
      const oracle = await withRequestTransaction(
        pool,
        actor.context,
        async (client) => {
          const original = await client.query<{ view: JsonValue }>(ORIGINAL_VOTE_TOOL_SQL, [
            voteId,
            actor.memberId
          ]);
          const metadata = await client.query<VoteToolProjectionMetadata>(VOTE_TOOL_PREFLIGHT_SQL, [
            voteId,
            actor.memberId
          ]);
          const raw = await client.query<{
            payload: Buffer;
            payload_json: string;
            resolution_id: string;
            package_id: string;
          }>(
            `select package.canonical_payload as payload,(convert_from(package.canonical_payload,'UTF8')::jsonb)::text as payload_json,
            vote.current_resolution_version_id as resolution_id,vote.current_decision_package_id as package_id
           from votes as vote left join decision_packages as package on package.id=vote.current_decision_package_id
           where vote.id=$1 and not boardagent_member_vote_recused(vote.id,$2)`,
            [voteId, actor.memberId]
          );
          // This deliberately reads the three synthetic rows under the real role
          // before occupancy. It proves unrelated rows are visible to RLS but are
          // excluded by the tool's additional principal-or-caster predicate.
          // Declared base RLS is organization+board scope (0011:79–114); this
          // actual-role assertion checks that premise on the installed fixture.
          // No claim about unreviewed later policy bodies is inferred beforehand.
          const ballots = await client.query<{
            ballot_id: string;
            principal_member_id: string;
            caster_member_id: string;
            choice: string;
            statement: string | null;
            voting_weight: string;
            source: string;
            cast_at: string;
          }>(
            `select id as ballot_id,principal_member_id,caster_member_id,choice,statement_text as statement,
          voting_weight::text as voting_weight,ballot_source as source,
          to_char(cast_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as cast_at
          from ballots where vote_id=$1`,
            [voteId]
          );
          expect(original.rows).toHaveLength(1);
          expect(metadata.rows).toHaveLength(1);
          expect(raw.rows).toHaveLength(1);
          expect(ballots.rows.map((row) => row.ballot_id).sort()).toEqual([...allIds].sort());
          const expected = ballots.rows
            .filter(
              (row) =>
                row.principal_member_id === actor.memberId ||
                row.caster_member_id === actor.memberId
            )
            .sort((left, right) =>
              left.cast_at < right.cast_at
                ? -1
                : left.cast_at > right.cast_at
                  ? 1
                  : left.ballot_id < right.ballot_id
                    ? -1
                    : left.ballot_id > right.ballot_id
                      ? 1
                      : 0
            );
          expect(expected.map((row) => row.ballot_id).sort()).toEqual([...selectedIds].sort());
          const q = object(original.rows[0]!.view);
          expect(q["my_ballots"]).toEqual(expected);
          expect(Object.keys(q)).toHaveLength(14);
          expect(Object.keys(object(q["resolution"]))).toHaveLength(4);
          expect(Object.keys(object(q["decision_package"]))).toHaveLength(12);
          for (const ballot of expected) expect(Object.keys(ballot)).toHaveLength(8);
          const m = metadata.rows[0]!,
            rawValue = raw.rows[0]!,
            flat = flatRoot(q);
          const ballotValues = expected.map((b) => flatBallot(b));
          const s = [...flat, ...ballotValues.flat()].reduce<number>(
            (sum, value) => sum + (value === null ? 0 : Buffer.byteLength(String(value))),
            0
          );
          const jsonShape = shape(JSON.parse(rawValue.payload_json));
          expect(m.row_count).toBe("1");
          expect(m.ballot_count).toBe(String(expected.length));
          expect(m.outcome_count).toBe("0");
          expect(m.scalar_utf8).toBe(String(s));
          expect(m.json_utf8).toBe(String(Buffer.byteLength(rawValue.payload_json)));
          expect(m.json_properties).toBe(String(jsonShape.properties));
          expect(m.json_containers).toBe(String(jsonShape.containers));
          // Independently hash each actual ordered ballot tuple and actual raw
          // package/resolution data. Stored commitments alone are not this oracle.
          const rowTuple = [...flat];
          rowTuple[12] = digest(String(object(q["resolution"])["canonical_text"]));
          rowTuple.push(
            rawValue.resolution_id,
            rawValue.package_id,
            rawValue.payload.length,
            digest(rawValue.payload),
            null
          );
          const tuples = ballotValues.map((values) => {
            const copy = [...values];
            copy[4] = copy[4] === null ? null : digest(String(copy[4]));
            return copy;
          });
          const hashed = await client.query<{ ordinal: string; sha: string }>(
            `select ordinal::text,encode(sha256(convert_to(value::text,'UTF8')),'hex') as sha
           from jsonb_array_elements($1::jsonb) with ordinality as entry(value,ordinal) order by entry.ordinal`,
            [JSON.stringify([rowTuple, ...tuples])]
          );
          expect(hashed.rows).toHaveLength(1 + expected.length);
          const observation = await client.query<{ sha: string }>(
            "select encode(sha256(convert_to(($1::jsonb)::text,'UTF8')),'hex') as sha",
            [
              JSON.stringify([
                voteId,
                actor.memberId,
                hashed.rows[0]!.sha,
                digest(
                  hashed.rows
                    .slice(1)
                    .map((row) => row.sha)
                    .join("")
                )
              ])
            ]
          );
          expect(m.observation_sha256).toBe(observation.rows[0]!.sha);
          const cost = voteToolProjectionCost(m),
            actual = shape(q);
          expect(bytes(q).length).toBeLessThanOrEqual(Number(cost.jsonUpperBytes));
          expect(actual.properties).toBeLessThanOrEqual(Number(cost.propertyCount));
          expect(actual.containers).toBeLessThanOrEqual(Number(cost.objectOrArrayCount));
          return { rows: original.rows, q, metadata: m, ballots: expected };
        },
        { assumeRole: "boardagent_server" }
      );
      const admitted = await read(actor);
      expect(admitted).toEqual(oracle.rows);
      expect(bytes(admitted)).toEqual(bytes(oracle.rows));
      return oracle;
    }
    const firstA = await verify(
      actorA,
      [proxy.ballotId, ownA.ballotId],
      [proxy.ballotId, ownA.ballotId]
    );
    const firstB = await verify(actorB, [proxy.ballotId, ownA.ballotId], [proxy.ballotId]);
    expect(firstA.ballots.find((b) => b.ballot_id === proxy.ballotId)).toMatchObject({
      principal_member_id: actorB.memberId,
      caster_member_id: actorA.memberId,
      source: "proxy"
    });
    expect(firstB.ballots[0]).toMatchObject({ ballot_id: proxy.ballotId, source: "proxy" });
    const before = constructedRows;
    await expect(
      read(actorB, {
        afterPreflight: async (metadata) => {
          expect(metadata.ballot_count).toBe("1");
          await withRequestTransaction(
            pool,
            actorB.context,
            (client) => castBallotInTransaction(client, ownB),
            { assumeRole: "boardagent_server" }
          );
        }
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    expect(constructedRows).toBe(before);
    const allIds = [proxy.ballotId, ownA.ballotId, ownB.ballotId];
    const finalA = await verify(actorA, allIds, [proxy.ballotId, ownA.ballotId]);
    const finalB = await verify(actorB, allIds, [proxy.ballotId, ownB.ballotId]);
    // Original reads include historical proxy evidence after the principal's own
    // ballot. Do not introduce an active-ballot-only filter in this projection.
    expect(finalB.ballots.map((b) => b.source)).toContain("proxy");
    expect(finalB.ballots.map((b) => b.source)).toContain("own");
    process.stdout.write(
      JSON.stringify({
        kind: "vote-tool-actual-ballot-observation",
        initialRootVersion: firstB.q["row_version"],
        finalRootVersion: finalB.q["row_version"],
        rootVersionUnchanged: firstB.q["row_version"] === finalB.q["row_version"],
        initialCallerBallots: firstB.metadata.ballot_count,
        finalCallerBallots: finalB.metadata.ballot_count,
        actorACastTimes: finalA.ballots.map((b) => ({ id: b.ballot_id, at: b.cast_at })),
        sameTimestampTieObserved: finalA.ballots[0]!.cast_at === finalA.ballots[1]!.cast_at
      }) + "\n"
    );
    for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
      for (const falseParameter of [2, 3, 4, 5, 6, 7, 8, 9, 10]) {
        const calls = contentCalls,
          count = constructedRows;
        await expect(read(actorA, { mode, fault: true, falseParameter })).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
        expect(contentCalls).toBe(calls + 1);
        expect(constructedRows).toBe(count);
      }
      // Both modes must reach a real entitled nested aggregate argument on the
      // true arm; empty-ballot success cannot stand in for this positive control.
      await expect(read(actorA, { mode, fault: true })).rejects.toThrow(
        "vote tool nested ballot value fault"
      );
      expect(manager.accounting.usedUnits).toBe(0);
    }
  });
});
