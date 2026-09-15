import { createHash, createHmac } from "node:crypto";
import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import { TOOL_INPUT_SCHEMA_VERSION } from "../../lib/contracts/src/surface-inputs.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  GOVERNANCE_LIST_PREFLIGHT_SQL,
  GOVERNANCE_LIST_CONTENT_SQL,
  loadAdmittedGovernanceList,
  governanceListProjectionCost,
  type GovernanceListInput,
  type GovernanceListKind,
  type GovernanceListMetadata
} from "../../artifacts/server/src/governance-list-projection.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { seedAuthorizedActor, testId } from "../helpers/authorized-actor.js";
import { meetingProjectionPrincipal } from "../helpers/meeting-projection-principal.js";
import { seedGovernanceListProjectionFixture } from "../helpers/governance-list-projection-fixture.js";
import { ORIGINAL_GOVERNANCE_LIST_SQL } from "../helpers/governance-lists-original-sql.js";
import {
  governanceListOriginalMetadataSQL,
  governanceListOriginalKeys,
  governanceListOriginalGraph
} from "../helpers/governance-lists-postgres-oracle.js";
type Row = { item: Record<string, JsonValue>; cursor_at: string | null; cursor_id: string };
type Metadata = { -readonly [K in keyof GovernanceListMetadata]: GovernanceListMetadata[K] };
const kinds = ["rulesets", "templates", "matter_types"] as const;
const tools = {
  rulesets: "list_ruleset_versions",
  templates: "list_approval_rule_templates",
  matter_types: "list_matter_types"
} as const;
const digest = (v: string) => createHash("sha256").update(v).digest("hex");
const parameters = (input: GovernanceListInput) => [
  input.boardId,
  input.cursorAt,
  input.cursorId,
  input.limit + 1
];
const total = (rows: readonly GovernanceListMetadata[]) => ({
  row_count: String(rows.length),
  scalar_utf8: String(rows.reduce((a, r) => a + BigInt(r.scalar_utf8), 0n)),
  normalized_json_utf8: String(rows.reduce((a, r) => a + BigInt(r.normalized_json_utf8), 0n)),
  json_property_count: String(rows.reduce((a, r) => a + BigInt(r.json_property_count), 0n)),
  json_container_count: String(rows.reduce((a, r) => a + BigInt(r.json_container_count), 0n))
});
function replaceOnce(sql: string, from: string, to: string) {
  expect(sql.split(from)).toHaveLength(2);
  return sql.replace(from, to);
}
function finish(owner: ReturnType<ResponseAllocationManager["openRequest"]>) {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
}
function signCursor(
  tool: string,
  organization: string,
  member: string,
  board: string,
  at: string | null,
  id: string,
  expires: number
) {
  const raw = canonicalJson({
    schema_version: "boardagent.cursor.v1",
    organization_id: organization,
    member_id: member,
    board_id: board,
    tool,
    after: canonicalJson({ at, id }),
    expires_at: expires
  });
  return (
    Buffer.from(raw).toString("base64url") +
    "." +
    createHmac("sha256", Buffer.alloc(32, 1))
      .update("boardagent.cursor.v1\0")
      .update(raw)
      .digest("base64url")
  );
}
it("admits exact governance catalog pages with actual metadata and fresh constructor gates", async () => {
  await withMigratedDatabase("governance_lists_projection", async (pool) => {
    const actor = await seedAuthorizedActor(pool, {
      seatRole: "voting_member",
      isSecretary: true,
      scopes: [
        "documents:contribute",
        "documents:read",
        "governance:read",
        "meeting:act",
        "secretariat:admin"
      ]
    });
    const seed = await seedGovernanceListProjectionFixture(pool, actor);
    const principal = await meetingProjectionPrincipal(pool, actor),
      manager = new ResponseAllocationManager();
    const repo = new PgSurfaceReadRepository(pool, { cursorKey: Buffer.alloc(32, 1) });
    const records: unknown[] = [];
    let falseControls = 0,
      trueControls = 0,
      publicCalls = 0;
    const input = (
      kind: GovernanceListKind,
      limit = 100,
      cursorAt: string | null = null,
      cursorId: string | null = null
    ): GovernanceListInput => ({ kind, boardId: actor.boardId, limit, cursorAt, cursorId });
    function role<T>(work: (client: PoolClient) => Promise<T>, context = actor.context) {
      return withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
    }
    async function owned<T>(work: () => Promise<T>) {
      const owner = manager.openRequest(new AbortController().signal);
      try {
        return await owner.produce(work);
      } finally {
        finish(owner);
      }
    }
    const catalog = await pool.query(
      `select c.relname,c.relrowsecurity,c.relforcerowsecurity,
      exists(select 1 from pg_constraint as p where p.conrelid=c.oid and p.contype='p' and p.convalidated
      and p.conkey=array[(select a.attnum from pg_attribute as a where a.attrelid=c.oid and a.attname='id')]::smallint[]) as id_primary
      from pg_class as c where c.relnamespace='public'::regnamespace and c.relname=any($1::text[]) order by c.relname`,
      [["boards", "rulesets", "governance_rule_templates", "matter_types"]]
    );
    expect(catalog.rows).toHaveLength(4);
    for (const row of catalog.rows)
      expect(row).toEqual({
        relname: row.relname,
        relrowsecurity: true,
        relforcerowsecurity: true,
        id_primary: true
      });
    records.push({ catalog: catalog.rows });
    async function inspect(selector: GovernanceListInput) {
      return role(async (client) => {
        const old = await client.query<Row>(
          ORIGINAL_GOVERNANCE_LIST_SQL[selector.kind],
          parameters(selector)
        );
        const measured = await client.query<GovernanceListMetadata>(
          GOVERNANCE_LIST_PREFLIGHT_SQL[selector.kind],
          parameters(selector)
        );
        const oracle = await client.query<GovernanceListMetadata>(
          governanceListOriginalMetadataSQL(selector.kind),
          parameters(selector)
        );
        expect(measured.rows).toEqual(oracle.rows);
        expect(measured.rows).toHaveLength(old.rows.length);
        for (const row of old.rows) {
          expect(Object.keys(row.item).sort()).toEqual(
            [...governanceListOriginalKeys[selector.kind]].sort()
          );
          const key =
            selector.kind === "templates"
              ? "exact_rule"
              : selector.kind === "matter_types"
                ? "strict_fact_schema"
                : null;
          if (key) {
            const graph = governanceListOriginalGraph(row.item[key]!);
            const meta = measured.rows.find((m) => m.id === row.cursor_id)!;
            expect(Number(meta.json_property_count)).toBe(graph.properties);
            expect(Number(meta.json_container_count)).toBe(graph.containers);
          }
        }
        const loaded = await owned(() => loadAdmittedGovernanceList(client, selector));
        expect(
          loaded.map(({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id }))
        ).toEqual(old.rows);
        const cost = governanceListProjectionCost(selector.kind, total(measured.rows));
        expect(Buffer.byteLength(JSON.stringify(loaded))).toBeLessThanOrEqual(
          Number(cost.jsonUpperBytes)
        );
        records.push({
          kind: selector.kind,
          limit: selector.limit,
          rows: old.rows.length,
          metadata: measured.rows,
          cost,
          old_sha256: digest(canonicalJson(old.rows as unknown as JsonValue))
        });
        return { old: old.rows, metadata: measured.rows };
      });
    }
    async function publicPage(selector: GovernanceListInput, cursor: string | null = null) {
      const { old } = await inspect(selector);
      const started = Math.floor(Date.now() / 1000);
      const actual = await owned(() =>
        repo.executeRead(principal, tools[selector.kind], {
          schema_version: TOOL_INPUT_SCHEMA_VERSION,
          board_id: actor.boardId,
          limit: selector.limit,
          ...(cursor ? { cursor } : {})
        })
      );
      const ended = Math.floor(Date.now() / 1000),
        data = actual.data as { items: JsonValue[]; next_cursor: string | null };
      let next: string | null = null;
      if (old.length > selector.limit) {
        expect(typeof data.next_cursor).toBe("string");
        const payload = JSON.parse(
          Buffer.from(data.next_cursor!.split(".")[0]!, "base64url").toString("utf8")
        ) as { expires_at: number };
        expect(payload.expires_at).toBeGreaterThanOrEqual(started + 86400);
        expect(payload.expires_at).toBeLessThanOrEqual(ended + 86400);
        const last = old[selector.limit - 1]!;
        next = signCursor(
          tools[selector.kind],
          actor.organizationId,
          actor.memberId,
          actor.boardId,
          last.cursor_at,
          last.cursor_id,
          payload.expires_at
        );
      }
      const expected = {
        schema_version: "boardagent.tool-result.v1",
        tool: tools[selector.kind],
        status: "ok",
        reference: null,
        resource_uri: null,
        data: { items: old.slice(0, selector.limit).map((r) => r.item), next_cursor: next }
      };
      expect(actual).toEqual(expected);
      expect(canonicalJson(actual)).toBe(canonicalJson(expected));
      records.push({
        public: tools[selector.kind],
        rows: data.items.length,
        has_next: next !== null,
        sha256: digest(canonicalJson(actual))
      });
      publicCalls++;
      return { old, actual };
    }
    for (const kind of kinds) {
      const selector = input(kind),
        all = await publicPage(selector);
      expect(all.old.length).toBe(kind === "rulesets" ? 2 : 3);
      const page = await publicPage(input(kind, 1)),
        cursor = (page.actual.data as { next_cursor: string }).next_cursor;
      const anchor = JSON.parse(
        JSON.parse(Buffer.from(cursor.split(".")[0]!, "base64url").toString("utf8")).after
      ) as { at: string; id: string };
      const tail = await publicPage(input(kind, 100, anchor.at, anchor.id), cursor);
      expect(tail.old).toHaveLength(all.old.length - 1);
      const last = all.old.at(-1)!,
        emptyCursor = signCursor(
          tools[kind],
          actor.organizationId,
          actor.memberId,
          actor.boardId,
          last.cursor_at,
          last.cursor_id,
          Math.floor(Date.now() / 1000) + 86400
        );
      expect(
        (await publicPage(input(kind, 100, last.cursor_at, last.cursor_id), emptyCursor)).old
      ).toEqual([]);
      const { metadata } = await inspect(selector);
      const idField =
        kind === "rulesets"
          ? "ruleset_id"
          : kind === "templates"
            ? "template_id"
            : "matter_type_id";
      const fault = replaceOnce(
        GOVERNANCE_LIST_CONTENT_SQL[kind],
        `'${idField}',chosen.id`,
        `'${idField}',(1/(0*random())::integer)`
      );
      for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
        for (const field of [
          "id",
          "cursor_at",
          "raw_order_key",
          "observation_sha256",
          "scalar_utf8",
          "normalized_json_utf8",
          "json_property_count",
          "json_container_count"
        ] as const) {
          const bad = metadata.map((m) => ({ ...m })) as Metadata[],
            first = bad[0]!;
          if (field === "id") first.id = testId(349999);
          else if (field === "cursor_at") first.cursor_at = "different";
          else if (field === "raw_order_key")
            first.raw_order_key = kind === "rulesets" ? "2001-01-01 00:00:00+00" : "zzzz";
          else if (field === "observation_sha256") first.observation_sha256 = "0".repeat(64);
          else first[field] = String(BigInt(first[field]) - 1n);
          // Intentionally changed private SQL-bound tuple, not a public negative scalar input.
          const blocked = await role(async (client) => {
            await client.query("set local plan_cache_mode=" + mode);
            return client.query({
              name: "gl_fault_" + kind,
              text: fault,
              values: [...parameters(selector), JSON.stringify(bad)]
            });
          });
          expect(blocked.rows).toEqual([
            { fits: false, item: null, cursor_at: null, cursor_id: null }
          ]);
          falseControls++;
        }
        await expect(
          role(async (client) => {
            await client.query("set local plan_cache_mode=" + mode);
            return client.query({
              name: "gl_fault_" + kind,
              text: fault,
              values: [...parameters(selector), JSON.stringify(metadata)]
            });
          })
        ).rejects.toMatchObject({ code: "22012" });
        trueControls++;
      }
      const occupied = manager.openRequest(new AbortController().signal);
      try {
        await occupied.produce(async () => {
          for (let i = 0; i < 2048; i++)
            occupied.reserve(
              responseAllocationPlan({
                kind: "document",
                representation: "tool",
                canonicalBytes: 1,
                sourceId: "small",
                sourceVersion: "1",
                sha256: "a".repeat(64)
              })
            );
        });
        await role(async (client) => {
          let queries = 0;
          const connection = {
            query: async (sql: string, values: unknown[]) => {
              queries++;
              return client.query(sql, values);
            }
          } as unknown as PoolClient;
          await expect(
            owned(() => loadAdmittedGovernanceList(connection, selector))
          ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
          expect(queries).toBe(1);
        });
      } finally {
        finish(occupied);
      }
      for (const context of [
        { ...actor.context, organizationId: testId(349998) },
        { ...actor.context, boardIds: [] }
      ]) {
        await role(async (client) => {
          expect(
            (await client.query(ORIGINAL_GOVERNANCE_LIST_SQL[kind], parameters(selector))).rows
          ).toEqual([]);
          expect(await owned(() => loadAdmittedGovernanceList(client, selector))).toEqual([]);
        }, context);
      }
      // Query-only equal-cost returned-value variants, never immutable stored-row edits.
      const from =
        kind === "rulesets"
          ? "ruleset.id,ruleset.version,"
          : kind === "templates"
            ? "template.exact_rule_payload as json_payload"
            : "matter.code,matter.name,";
      const to =
        kind === "rulesets"
          ? "ruleset.id,ruleset.version+1 as version,"
          : kind === "templates"
            ? "(template.exact_rule_payload || jsonb_build_object('label','Survey Δ')) as json_payload"
            : "matter.code,replace(matter.name,'Mining','Survey') as name,";
      const fresh = await role((client) =>
        client.query<GovernanceListMetadata>(
          replaceOnce(GOVERNANCE_LIST_PREFLIGHT_SQL[kind], from, to),
          parameters(selector)
        )
      );
      expect(total(fresh.rows)).toEqual(total(metadata));
      expect(fresh.rows[0]!.observation_sha256).not.toBe(metadata[0]!.observation_sha256);
      expect(
        (
          await role((client) =>
            client.query(replaceOnce(GOVERNANCE_LIST_CONTENT_SQL[kind], from, to), [
              ...parameters(selector),
              JSON.stringify(metadata)
            ])
          )
        ).rows
      ).toEqual([{ fits: false, item: null, cursor_at: null, cursor_id: null }]);
    }
    expect(falseControls).toBe(48);
    expect(trueControls).toBe(6);
    expect(publicCalls).toBe(12);
    // Normal guarded current-pointer change: known catalogs disappear. No profile activation claimed.
    const oldTemplate = await role((client) =>
      client.query<GovernanceListMetadata>(
        GOVERNANCE_LIST_PREFLIGHT_SQL.templates,
        parameters(input("templates"))
      )
    );
    const oldMatter = await role((client) =>
      client.query<GovernanceListMetadata>(
        GOVERNANCE_LIST_PREFLIGHT_SQL.matter_types,
        parameters(input("matter_types"))
      )
    );
    const changed = await pool.query(
      "update boards set current_governance_profile_id=$2,current_ruleset_id=$3,row_version=row_version+1 where id=$1 returning id",
      [actor.boardId, seed.alternateProfileId, seed.alternateRulesetId]
    );
    expect(changed.rowCount).toBe(1);
    for (const [kind, metadata] of [
      ["templates", oldTemplate.rows],
      ["matter_types", oldMatter.rows]
    ] as const) {
      const selected = input(kind);
      expect(
        (
          await role((client) =>
            client.query(GOVERNANCE_LIST_CONTENT_SQL[kind], [
              ...parameters(selected),
              JSON.stringify(metadata)
            ])
          )
        ).rows
      ).toEqual([]);
      expect((await inspect(selected)).old).toEqual([]);
    }
    expect(manager.accounting.usedUnits).toBe(0);
    console.log(
      "GOVERNANCE_LIST_PG_OBSERVATIONS",
      JSON.stringify({
        falseControls,
        trueControls,
        publicCalls,
        records,
        finalUnits: manager.accounting.usedUnits
      })
    );
  });
}, 120000);
