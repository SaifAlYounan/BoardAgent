import { createHash } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  GOVERNANCE_PROFILE_TOOL_PREFLIGHT_SQL,
  GOVERNANCE_PROFILE_TOOL_CONTENT_SQL,
  RULESET_TOOL_PREFLIGHT_SQL,
  RULESET_TOOL_CONTENT_SQL,
  governanceToolProjectionCost,
  governanceToolProjectionPlan,
  loadAdmittedGovernanceToolProjection,
  type GovernanceToolSelector,
  type GovernanceToolProjectionMetadata
} from "../../artifacts/server/src/governance-tool-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { seedGovernanceToolProjectionFixture } from "../helpers/governance-tool-projection-fixture.js";
import {
  ORIGINAL_PROFILE_TOOL_SQL,
  ORIGINAL_RULESET_TOOL_SQL
} from "../helpers/governance-tool-original-sql.js";

type Kind = GovernanceToolSelector["kind"];
type View = Readonly<Record<string, JsonValue>>;
const preflight = {
  profile: GOVERNANCE_PROFILE_TOOL_PREFLIGHT_SQL,
  ruleset: RULESET_TOOL_PREFLIGHT_SQL
};
const content = { profile: GOVERNANCE_PROFILE_TOOL_CONTENT_SQL, ruleset: RULESET_TOOL_CONTENT_SQL };
const original = { profile: ORIGINAL_PROFILE_TOOL_SQL, ruleset: ORIGINAL_RULESET_TOOL_SQL };
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
function object(value: JsonValue | undefined): View {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError("expected original object");
  return value as View;
}
function shape(value: unknown) {
  const pending: unknown[] = [value];
  let properties = 0,
    containers = 0;
  while (pending.length) {
    const next = pending.pop();
    if (next !== null && typeof next === "object") {
      containers += 1;
      if (!Array.isArray(next)) properties += Object.keys(next).length;
      for (const child of Object.values(next)) pending.push(child);
    }
  }
  return { properties, containers };
}
function flat(kind: Kind, view: View): readonly JsonValue[] {
  // Independent inventory of the preserved original9/10/6 flat values.
  const values =
    kind === "profile"
      ? [
          view["profile_id"],
          view["board_id"],
          view["version"],
          view["state"],
          view["schema_version"],
          view["sha256"],
          view["supersedes_id"],
          view["created_at"],
          view["activated_at"]
        ]
      : [
          view["ruleset_id"],
          view["board_id"],
          view["profile_id"],
          view["version"],
          view["state"],
          view["schema_version"],
          view["sha256"],
          view["supersedes_id"],
          view["created_at"],
          view["activated_at"]
        ];
  if (kind === "ruleset")
    for (const entry of view["rules"] as readonly JsonValue[]) {
      const rule = object(entry);
      values.push(
        rule["rule_id"],
        rule["matter_type_id"],
        rule["priority"],
        rule["specificity"],
        rule["approval_rule_id"],
        rule["sha256"]
      );
    }
  if (values.some((value) => value === undefined))
    throw new TypeError("missing original flat field");
  return values as JsonValue[];
}
const pgHash = (expression: string) =>
  `encode(sha256(convert_to((${expression})::text,'UTF8')),'hex')`;
function observationOracle(kind: Kind) {
  // Hash the independently preserved ORIGINAL full view entirely inside PG.
  // This intentionally constructs the old result before any occupancy phase.
  const keys =
    kind === "profile"
      ? [
          "profile_id",
          "board_id",
          "version",
          "state",
          "schema_version",
          "sha256",
          "supersedes_id",
          "created_at",
          "activated_at"
        ]
      : [
          "ruleset_id",
          "board_id",
          "profile_id",
          "version",
          "state",
          "schema_version",
          "sha256",
          "supersedes_id",
          "created_at",
          "activated_at"
        ];
  const children = pgHash(`coalesce((select string_agg(${pgHash(`jsonb_build_array(
    rule.value->'rule_id',rule.value->'matter_type_id',rule.value->'priority',rule.value->'specificity',
    rule.value->'approval_rule_id',rule.value->'sha256',${pgHash("rule.value->'condition'")})`)},'' order by rule.ordinality)
    from jsonb_array_elements(v.view->'rules') with ordinality as rule(value,ordinality)),'')`);
  return `with v as (${original[kind]}) select ${pgHash(`jsonb_build_array(${keys.map((key) => `v.view->'${key}'`).join(",")},
    ${pgHash("v.view->'canonical_payload'")},${kind === "profile" ? pgHash("v.view->'source_agreement_references'") : children})`)} as observation_sha256 from v`;
}
function parameters(input: GovernanceToolSelector): unknown[] {
  return [input.boardId, input.kind === "profile" ? input.version : input.rulesetId];
}
function bound(
  input: GovernanceToolSelector,
  metadata: GovernanceToolProjectionMetadata
): unknown[] {
  return [
    ...parameters(input),
    metadata.entity_id,
    metadata.version,
    metadata.observation_sha256,
    metadata.rule_count,
    metadata.scalar_utf8,
    metadata.json_utf8,
    metadata.json_properties,
    metadata.json_containers
  ];
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

it("admits exact governance tool projections with actual scalar/private bindings and complete fresh gates", async () => {
  await withMigratedDatabase("governance_tool", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: ["governance:read", "secretariat:admin"]
    });
    const seed = await seedGovernanceToolProjectionFixture(pool, actor);
    const manager = new ResponseAllocationManager();
    const records: unknown[] = [];
    function role<T>(work: (client: PoolClient) => Promise<T>, context = actor.context) {
      return withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
    }
    const catalog = await pool.query(
      `select table_info.relname,table_info.relrowsecurity,table_info.relforcerowsecurity,
      exists(select 1 from pg_constraint as key where key.conrelid=table_info.oid and key.contype='p'
        and array_length(key.conkey,1)=1 and key.conkey[1]=(select attribute.attnum from pg_attribute as attribute
          where attribute.attrelid=table_info.oid and attribute.attname='id' and not attribute.attisdropped)) as single_id_primary_key
      from pg_class as table_info where table_info.relnamespace='public'::regnamespace
        and table_info.relname=any($1::text[]) order by table_info.relname`,
      [["boards", "governance_profiles", "rulesets", "ruleset_rules"]]
    );
    expect(catalog.rows).toHaveLength(4);
    for (const row of catalog.rows)
      expect(row).toEqual({
        relname: row.relname,
        relrowsecurity: true,
        relforcerowsecurity: true,
        single_id_primary_key: true
      });
    const current = (kind: Kind): GovernanceToolSelector =>
      kind === "profile"
        ? { kind, boardId: actor.boardId, version: null }
        : { kind, boardId: actor.boardId, rulesetId: null };
    const explicit = (kind: Kind, alternate = false): GovernanceToolSelector =>
      kind === "profile"
        ? { kind, boardId: actor.boardId, version: alternate ? 2 : 1 }
        : {
            kind,
            boardId: actor.boardId,
            rulesetId: alternate ? seed.alternateRulesetId : seed.rulesetId
          };
    async function oracle(input: GovernanceToolSelector) {
      return role(async (client) => {
        expect((await client.query("select current_user")).rows[0].current_user).toBe(
          "boardagent_server"
        );
        const prior = await client.query<{ view: JsonValue }>(
          original[input.kind],
          parameters(input)
        );
        expect(prior.rows).toHaveLength(1);
        const view = object(prior.rows[0]!.view);
        expect(Object.keys(view)).toHaveLength(input.kind === "profile" ? 11 : 12);
        const entityId = String(view[input.kind === "profile" ? "profile_id" : "ruleset_id"]);
        const roots: JsonValue[] = [view["canonical_payload"]!];
        let raw: string[];
        if (input.kind === "profile") {
          roots.push(view["source_agreement_references"]!);
          const data = await client.query(
            `select canonical_payload::text as payload,
            source_agreement_references::text as refs from governance_profiles where id=$1`,
            [entityId]
          );
          raw = [data.rows[0].payload, data.rows[0].refs];
        } else {
          for (const entry of view["rules"] as readonly JsonValue[]) {
            const rule = object(entry);
            expect(Object.keys(rule)).toHaveLength(7);
            roots.push(rule["condition"]!);
          }
          const parent = await client.query(
            "select canonical_payload::text as payload from rulesets where id=$1",
            [entityId]
          );
          const children = await client.query(
            `select condition_tree::text as condition from ruleset_rules
            where ruleset_id=$1 order by priority desc,specificity desc,id`,
            [entityId]
          );
          raw = [parent.rows[0].payload, ...children.rows.map((row) => String(row.condition))];
        }
        const observation = await client.query<{ observation_sha256: string }>(
          observationOracle(input.kind),
          parameters(input)
        );
        const metrics = await client.query<GovernanceToolProjectionMetadata>(
          preflight[input.kind],
          parameters(input)
        );
        expect(metrics.rows).toHaveLength(1);
        const metadata = metrics.rows[0]!;
        let properties = 0,
          containers = 0;
        for (const root of roots) {
          const graph = shape(root);
          properties += graph.properties;
          containers += graph.containers;
        }
        expect(metadata).toEqual({
          entity_id: entityId,
          board_id: actor.boardId,
          version: Number(view["version"]),
          observation_sha256: observation.rows[0]!.observation_sha256,
          rule_count: String(
            input.kind === "profile" ? 0 : (view["rules"] as readonly JsonValue[]).length
          ),
          scalar_utf8: String(
            flat(input.kind, view).reduce<number>(
              (sum, value) => sum + (value === null ? 0 : Buffer.byteLength(String(value))),
              0
            )
          ),
          json_utf8: String(raw.reduce((sum, value) => sum + Buffer.byteLength(value), 0)),
          json_properties: String(properties),
          json_containers: String(containers)
        });
        const cost = governanceToolProjectionCost(input.kind, metadata);
        expect(BigInt(Buffer.byteLength(JSON.stringify(view)))).toBeLessThanOrEqual(
          BigInt(cost.jsonUpperBytes)
        );
        return { view, metadata, cost, bytes: canonicalJson(view) };
      });
    }
    async function read(
      input: GovernanceToolSelector,
      afterMetadata?: () => Promise<void>,
      occupied = false
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      let metadataCalls = 0,
        contentCalls = 0,
        observed: GovernanceToolProjectionMetadata | undefined;
      let failed = false,
        failure: unknown;
      try {
        return await owner.produce(() =>
          role(async (client) => {
            const intercepted = {
              query: async (sql: string, values?: unknown[]) => {
                if (sql === content[input.kind]) {
                  contentCalls += 1;
                  expect(manager.accounting.usedUnits).toBeGreaterThan(0);
                }
                const result = await client.query(sql, values);
                if (sql === preflight[input.kind]) {
                  metadataCalls += 1;
                  observed = result.rows[0] as GovernanceToolProjectionMetadata | undefined;
                  if (afterMetadata) await afterMetadata();
                }
                return result;
              }
            } as unknown as PoolClient;
            return loadAdmittedGovernanceToolProjection(intercepted, input);
          })
        );
      } catch (error) {
        failed = true;
        failure = error;
        throw error;
      } finally {
        const held = manager.accounting.usedUnits;
        let afterTerminal = held;
        try {
          owner.nativeTerminal();
          afterTerminal = manager.accounting.usedUnits;
        } finally {
          owner.collectorSettled();
        }
        records.push({
          kind: input.kind,
          selector: parameters(input)[1],
          metadataCalls,
          contentCalls,
          heldUnits: held,
          afterTerminal,
          afterCollector: manager.accounting.usedUnits,
          failureKind: failed ? (failure instanceof Error ? failure.name : "non-Error") : null
        });
        // Both settlement signals are unconditional. Preserve an underlying SQL
        // failure rather than replacing it with a missing-metadata diagnostic.
        if (!failed || failure instanceof ResponseAllocationUnavailable) {
          expect(metadataCalls).toBe(1);
          if (occupied) {
            expect(contentCalls).toBe(0);
            expect(held).toBe(2048);
          } else if (contentCalls && observed)
            expect(held).toBe(governanceToolProjectionPlan(input.kind, observed).units);
          expect(afterTerminal).toBe(held);
          expect(manager.accounting.usedUnits).toBe(occupied ? 2048 : 0);
        }
      }
    }
    // Independent original full-view and PG-text oracles run BEFORE occupancy.
    for (const kind of ["profile", "ruleset"] as const)
      for (const input of [current(kind), explicit(kind), explicit(kind, true)]) {
        const expected = await oracle(input),
          actual = await read(input);
        expect(actual).toEqual(expected.view);
        expect(canonicalJson(actual)).toBe(expected.bytes);
        if (
          kind === "ruleset" &&
          input.kind === "ruleset" &&
          input.rulesetId !== seed.alternateRulesetId
        )
          expect(
            (expected.view["rules"] as readonly JsonValue[]).map((rule) => object(rule)["rule_id"])
          ).toEqual(seed.ruleIds);
      }
    const carry = await role((client) =>
      client.query(`select '[9999999999999999]'::jsonb as value,
      '[9999999999999999]'::jsonb::text as raw`)
    );
    expect(carry.rows[0].raw).toBe("[9999999999999999]");
    expect(JSON.stringify(carry.rows[0].value)).toBe("[10000000000000000]");
    expect(Buffer.byteLength(JSON.stringify(carry.rows[0].value))).toBe(
      Buffer.byteLength(carry.rows[0].raw) + 1
    );
    const small = responseAllocationPlan({
      kind: "document",
      representation: "resource",
      sourceId: "small",
      sourceVersion: "1",
      sha256: "a".repeat(64),
      canonicalBytes: 1
    });
    const leases = Array.from({ length: 2048 }, () => manager.tryReserve(small));
    try {
      for (const kind of ["profile", "ruleset"] as const)
        await expect(read(current(kind), undefined, true)).rejects.toBeInstanceOf(
          ResponseAllocationUnavailable
        );
    } finally {
      for (const lease of leases) lease.release();
    }
    expect(manager.accounting.usedUnits).toBe(0);

    for (const kind of ["profile", "ruleset"] as const) {
      const input = current(kind),
        prior = await oracle(input);
      const wholeFault = content[kind].replace(
        "select jsonb_build_object(",
        "select jsonb_build_object('fixture_fault',(root.entity_id::text)::integer,"
      );
      const nestedFault = content[kind].replace(
        "'condition',rule.condition",
        "'condition',to_jsonb((rule.rule_id::text)::integer)"
      );
      expect(wholeFault).not.toBe(content[kind]);
      const variants = kind === "profile" ? [wholeFault] : [wholeFault, nestedFault];
      if (kind === "ruleset") expect(nestedFault).not.toBe(content[kind]);
      for (const mode of ["force_custom_plan", "force_generic_plan"] as const)
        for (const [index, sql] of variants.entries()) {
          for (let component = 2; component < 10; component += 1) {
            const values = bound(input, prior.metadata);
            values[component] =
              component === 2
                ? testId(399999)
                : component === 3
                  ? 2
                  : component === 4
                    ? "f".repeat(64)
                    : component === 5
                      ? String(BigInt(prior.metadata.rule_count) + 1n)
                      : String(BigInt(String(values[component])) - 1n);
            const result = await role(async (client) => {
              await client.query(`set local plan_cache_mode='${mode}'`);
              return client.query({
                name: `governance-${kind}-${mode}-${index}`,
                text: sql,
                values
              });
            });
            expect(result.rows).toHaveLength(1);
            expect(result.rows[0].fits).toBe(false);
            expect(result.rows[0].view).toBeNull();
          }
          await expect(
            role(async (client) => {
              await client.query(`set local plan_cache_mode='${mode}'`);
              return client.query({
                name: `governance-${kind}-${mode}-${index}`,
                text: sql,
                values: bound(input, prior.metadata)
              });
            })
          ).rejects.toMatchObject({ code: "22P02" });
        }
      const wrong = { ...input, boardId: testId(399998) };
      expect(await read(wrong)).toBeNull();
    }

    // Committed normal parent changes keep IDs/version/stored commitment and
    // costs equal. Exact private actual-JSON binding must refuse in-flight.
    for (const [kind, column] of [
      ["profile", "canonical_payload"],
      ["profile", "source_agreement_references"],
      ["ruleset", "canonical_payload"]
    ] as const) {
      const input = current(kind),
        prior = await oracle(input);
      const table = kind === "profile" ? "governance_profiles" : "rulesets";
      await expect(
        read(input, async () => {
          const result = await pool.query(
            `update ${table} set ${column}=${column === "source_agreement_references" ? "'[9999999999999998]'::jsonb" : "jsonb_set(canonical_payload,'{marker}','\"B\"'::jsonb)"} where id=$1 returning id`,
            [prior.metadata.entity_id]
          );
          expect(result.rows).toHaveLength(1);
        })
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      const fresh = await oracle(input);
      expect({ ...fresh.metadata, observation_sha256: prior.metadata.observation_sha256 }).toEqual(
        prior.metadata
      );
      expect(fresh.metadata.observation_sha256).not.toBe(prior.metadata.observation_sha256);
      expect(fresh.view["sha256"]).toBe(prior.view["sha256"]);
      expect(await read(input)).toEqual(fresh.view);
    }
    const priorRules = await oracle(current("ruleset"));
    await expect(
      read(current("ruleset"), async () => {
        await pool.query(
          `insert into ruleset_rules(id,ruleset_id,matter_type_id,priority,specificity,
        condition_tree,approval_rule_id,canonical_sha256) values($1,$2,$3,30,1,$4::jsonb,$5,$6)`,
          [
            testId(310014),
            seed.rulesetId,
            seed.matterTypeId,
            seed.conditionText,
            seed.approvalRuleId,
            Buffer.alloc(32, 7)
          ]
        );
      })
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const grown = await oracle(current("ruleset"));
    expect(grown.metadata.rule_count).toBe("5");
    expect(grown.view["sha256"]).toBe(priorRules.view["sha256"]);
    expect(object((grown.view["rules"] as readonly JsonValue[])[0])["rule_id"]).toBe(
      testId(310014)
    );
    expect(await read(current("ruleset"))).toEqual(grown.view);

    for (const kind of ["profile", "ruleset"] as const) {
      // Switch coherent pointer pairs atomically; this does not assume that a
      // temporary profile/ruleset mismatch is permitted by installed guards.
      await pool.query(
        `update boards set current_governance_profile_id=$2,current_ruleset_id=$3,
        row_version=row_version+1 where id=$1`,
        [actor.boardId, seed.profileId, seed.rulesetId]
      );
      await expect(
        read(current(kind), async () => {
          await pool.query(
            `update boards set current_governance_profile_id=$2,current_ruleset_id=$3,
          row_version=row_version+1 where id=$1`,
            [actor.boardId, seed.alternateProfileId, seed.alternateRulesetId]
          );
        })
      ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(await read(current(kind))).toEqual((await oracle(explicit(kind, true))).view);
      const emptyContext = { ...actor.context, boardIds: [] };
      const oldVisible = await role(
        (client) => client.query<{ view: JsonValue }>(original[kind], parameters(current(kind))),
        emptyContext
      );
      const owner = manager.openRequest(new AbortController().signal);
      try {
        expect(
          await owner.produce(() =>
            role(
              (client) => loadAdmittedGovernanceToolProjection(client, current(kind)),
              emptyContext
            )
          )
        ).toEqual(oldVisible.rows[0]?.view ?? null);
      } finally {
        owner.nativeTerminal();
        owner.collectorSettled();
      }
      records.push({ kind, emptyBoardContextOriginalVisibleRows: oldVisible.rows.length });
    }
    const controller = new AbortController(),
      owner = manager.openRequest(controller.signal),
      entered = gate(),
      finish = gate();
    const pending = owner.produce(() =>
      role(async (client) => {
        const held = {
          query: async (sql: string, values?: unknown[]) => {
            const result = await client.query(sql, values);
            if (sql === RULESET_TOOL_CONTENT_SQL) {
              entered.release();
              await finish.promise;
            }
            return result;
          }
        } as unknown as PoolClient;
        return loadAdmittedGovernanceToolProjection(held, explicit("ruleset"));
      })
    );
    const caught = pending.then(
      () => null,
      (error: unknown) => error
    );
    try {
      await Promise.race([
        entered.promise,
        pending.then(() => {
          throw new Error("real content query was not held");
        })
      ]);
      controller.abort();
      owner.nativeTerminal();
      owner.collectorSettled();
      expect(manager.accounting.usedUnits).toBeGreaterThan(0);
    } finally {
      finish.release();
      owner.nativeTerminal();
      owner.collectorSettled();
    }
    expect(await caught).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(manager.accounting.usedUnits).toBe(0);
    process.stdout.write(
      JSON.stringify({
        governanceToolProjection: {
          records,
          catalog: catalog.rows,
          numericCarry: carry.rows[0],
          originalShapeFields: [11, 12, 7],
          explicitGateComparisons: 8,
          separateWrongBoardAbsence: true,
          nativeSdkExecuted: false,
          publicGovernanceActivationExecuted: false,
          finalUsedUnits: manager.accounting.usedUnits,
          originalSqlHashes: {
            profile: digest(ORIGINAL_PROFILE_TOOL_SQL),
            ruleset: digest(ORIGINAL_RULESET_TOOL_SQL)
          }
        }
      }) + "\n"
    );
  });
});
