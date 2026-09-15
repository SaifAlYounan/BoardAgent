import { expect, it } from "vitest";
import type { PoolClient } from "pg";
import {
  canonicalJson,
  sha256Hex,
  TOOL_INPUT_SCHEMA_VERSION
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import type { SurfacePrincipal } from "../../artifacts/server/src/ports.js";
import {
  MINUTES_LIST_PREFLIGHT_SQL,
  MINUTES_LIST_CONTENT_SQL,
  loadAdmittedMinutesList,
  minutesListProjectionCost,
  minutesListProjectionPlan,
  type MinutesListInput,
  type MinutesListKind,
  type MinutesListMetadata
} from "../../artifacts/server/src/minutes-list-projection.js";
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
import {
  ORIGINAL_MINUTES_VERSIONS_SQL,
  ORIGINAL_MINUTES_REVIEWS_SQL
} from "../helpers/minutes-lists-original-sql.js";
import {
  independentListMetadata,
  listGraph,
  listTotals,
  minutesListCursorKey,
  minutesListTools,
  originalListEnvelope,
  originalObject,
  type MinutesOracleRow,
  type ListRawOracle
} from "../helpers/minutes-list-pg-oracle.js";

const originalSql = {
  versions: ORIGINAL_MINUTES_VERSIONS_SQL,
  reviews: ORIGINAL_MINUTES_REVIEWS_SQL
};
const identity = (sql: string) => sql;
const parameters = (input: MinutesListInput) => [
  input.minutesId,
  input.cursorAt,
  input.cursorId,
  input.limit + 1
];
const strip = (rows: readonly MinutesOracleRow[]) =>
  rows.map(({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id }));
const replaceOnce = (sql: string, from: string, to: string) => {
  expect(sql.split(from)).toHaveLength(2);
  return sql.replace(from, to);
};

it("admits original minutes list frontiers with normal review/version growth and guarded PostgreSQL construction", async () => {
  await withMigratedDatabase("minutes_lists_projection", async (pool) => {
    const fixture = await seedMinutesLineageFixture(pool),
      actor = fixture.secretary;
    await fixture.appendSuccessor();
    expect(fixture.commands).toHaveLength(12);
    const manager = new ResponseAllocationManager(),
      reports: unknown[] = [],
      contentHashes: string[] = [];
    const transaction = <T>(body: (client: PoolClient) => Promise<T>, context = actor.context) =>
      withRequestTransaction(pool, context, body, { assumeRole: "boardagent_server" });
    const input = (kind: MinutesListKind, limit = 100): MinutesListInput => ({
      kind,
      minutesId: fixture.replacementId,
      cursorAt: null,
      cursorId: null,
      limit
    });
    const original = (selection: MinutesListInput, transform = identity, context = actor.context) =>
      transaction(
        async (client) =>
          (
            await client.query<MinutesOracleRow>(
              transform(originalSql[selection.kind]),
              parameters(selection)
            )
          ).rows,
        context
      );
    const metadata = (selection: MinutesListInput, transform = identity) =>
      transaction(
        async (client) =>
          (
            await client.query<MinutesListMetadata>(
              transform(MINUTES_LIST_PREFLIGHT_SQL[selection.kind]),
              parameters(selection)
            )
          ).rows
      );
    const catalog = (
      await pool.query(`select c.relname,c.relrowsecurity,c.relforcerowsecurity,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indnkeyatts=1 and a.attname='id') as id_pk,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisunique and i.indisvalid and i.indisready and i.indnkeyatts=1
        and i.indpred is null and i.indexprs is null and a.attname='review_item_id' and a.attnotnull) as child_unique
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public'
      and c.relname in ('minutes_versions','minutes_review_items','minutes_review_withdrawals','minutes_review_dispositions') order by c.relname`)
    ).rows;
    expect(catalog).toHaveLength(4);
    for (const row of catalog)
      expect(row).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true, id_pk: true });
    for (const table of ["minutes_review_withdrawals", "minutes_review_dispositions"])
      expect(catalog.find((row) => row.relname === table)?.child_unique).toBe(true);
    expect(
      await transaction(async (client) => (await client.query("select current_user")).rows)
    ).toEqual([{ current_user: "boardagent_server" }]);

    async function read(
      selection: MinutesListInput,
      afterMetadata?: () => Promise<unknown>,
      transform = identity,
      context = actor.context
    ) {
      const owner = manager.openRequest(new AbortController().signal),
        baseline = manager.accounting.usedUnits;
      let preflights = 0,
        contents = 0,
        held = baseline,
        failure: unknown,
        rows: readonly MinutesOracleRow[] | undefined;
      try {
        rows = await owner.produce(() =>
          transaction(async (client) => {
            const proxy = Object.create(client) as PoolClient;
            proxy.query = (async (sql: string, values?: unknown[]) => {
              if (sql === MINUTES_LIST_PREFLIGHT_SQL[selection.kind]) {
                preflights++;
                const result = await client.query(transform(sql), values);
                await afterMetadata?.();
                return result;
              }
              if (sql === MINUTES_LIST_CONTENT_SQL[selection.kind]) contents++;
              return client.query(transform(sql), values);
            }) as PoolClient["query"];
            return loadAdmittedMinutesList(proxy, selection) as Promise<
              readonly MinutesOracleRow[]
            >;
          }, context)
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
        kind: selection.kind,
        limit: selection.limit,
        preflights,
        contents,
        held,
        finalUnits: manager.accounting.usedUnits,
        failed: failure !== undefined
      });
      try {
        expect(preflights).toBe(1);
        expect(manager.accounting.usedUnits).toBe(baseline);
      } catch (error) {
        if (failure !== undefined)
          throw new AggregateError([failure, error], "list SQL and accounting failed");
        throw error;
      }
      if (failure !== undefined) throw failure;
      return { rows: rows!, held, contents };
    }
    async function admittedSql(
      selection: MinutesListInput,
      observed: readonly MinutesListMetadata[],
      sql: string,
      name?: string,
      mode?: string
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      try {
        return await owner.produce(async () => {
          owner.reserve(minutesListProjectionPlan(selection, await metadata(selection)));
          return transaction(async (client) => {
            if (mode) await client.query(`set local plan_cache_mode=${mode}`);
            return client.query({
              text: sql,
              values: [...parameters(selection), JSON.stringify(observed)],
              ...(name ? { name } : {})
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
    async function verify(
      selection: MinutesListInput,
      transform = identity,
      anchorExpression = "item.exact_anchor",
      payloadExpression = "item.canonical_payload"
    ) {
      const old = await original(selection, transform),
        observed = await metadata(selection, transform);
      expect(observed).toHaveLength(old.length);
      const independent = await transaction(async (client) => {
        const result: MinutesListMetadata[] = [];
        for (const row of old) {
          const raw =
            selection.kind === "versions"
              ? (
                  await client.query<ListRawOracle>(
                    `select created_at::text as raw_created_at,null::text as anchor_text,null::text as payload_text,
                null::text as raw_sha256,null::integer as raw_length from minutes_versions where id=$1`,
                    [row.cursor_id]
                  )
                ).rows[0]!
              : (
                  await client.query<ListRawOracle>(
                    `select item.created_at::text as raw_created_at,(${anchorExpression})::text as anchor_text,
                convert_from((${payloadExpression}),'UTF8')::jsonb::text as payload_text,
                encode(sha256((${payloadExpression})),'hex') as raw_sha256,octet_length((${payloadExpression})) as raw_length
                from minutes_review_items as item where item.id=$1`,
                    [row.cursor_id]
                  )
                ).rows[0]!;
          result.push(await independentListMetadata(client, selection.kind, row, raw));
        }
        return result;
      });
      expect(observed).toEqual(independent);
      const cost = minutesListProjectionCost(selection.kind, listTotals(independent)),
        plan = minutesListProjectionPlan(selection, observed);
      const actual = await read(selection, undefined, transform);
      expect(strip(actual.rows)).toEqual(old);
      expect(actual.held).toBe(1);
      expect(actual.contents).toBe(1);
      const retained = actual.rows,
        graph = listGraph([retained], true);
      expect(graph.properties).toBeLessThanOrEqual(BigInt(cost.propertyCount));
      expect(graph.containers).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
      expect(BigInt(Buffer.byteLength(JSON.stringify(retained)))).toBeLessThanOrEqual(
        BigInt(cost.jsonUpperBytes)
      );
      expect(plan.units).toBe(1);
      const hash = sha256Hex(canonicalJson(strip(actual.rows)));
      contentHashes.push(hash);
      return { old, observed, cost, plan, hash };
    }
    await verify(input("versions"));
    expect((await verify(input("reviews"))).old).toEqual([]);
    const reviews = await fixture.minutesLists.seedReviews();
    expect((await verify(input("reviews"))).old).toHaveLength(3);
    await expect(
      read(input("reviews"), fixture.minutesLists.withdrawFirstComment)
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    let current = await verify(input("reviews"));
    expect(
      current.old.find((row) => row.cursor_id === reviews.firstComment)?.item["withdrawal"]
    ).not.toBeNull();
    await expect(
      read(input("reviews"), fixture.minutesLists.resolveRedline)
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    current = await verify(input("reviews"));
    expect(
      current.old.find((row) => row.cursor_id === reviews.redline)?.item["disposition"]
    ).toMatchObject({ decision: "rejected" });
    await fixture.minutesLists.withdrawSecondComment();
    await verify(input("reviews"));
    await fixture.minutesLists.appendVersion();
    await verify(input("versions"));
    await expect(
      read(input("versions"), fixture.minutesLists.appendVersion)
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const allVersions = await verify(input("versions")),
      allReviews = await verify(input("reviews"));
    expect(allVersions.old).toHaveLength(3);
    expect(allReviews.old).toHaveLength(3);
    expect(fixture.commands).toHaveLength(20);
    expect(allVersions.old.map((row) => row.item["version"])).toEqual([3, 2, 1]);
    expect(allReviews.old.map((row) => row.cursor_id).sort()).toEqual(
      [reviews.firstComment, reviews.secondComment, reviews.redline].sort()
    );

    // This ordinary repository test fixture has no browser session by default.
    // Add constrained synthetic authenticated-session storage for the real
    // live-token resolver; no browser or OAuth authentication is represented.
    const sessionId = testId(338004);
    await pool.query(
      `insert into auth_sessions(id,organization_id,opaque_session_sha256,member_id,client_id,
        state,exact_origin,expires_at,last_authenticated_at)
       values($1,$2,$3,$4,$5,'authenticated',$6,transaction_timestamp()+interval '10 minutes',
        transaction_timestamp())`,
      [
        sessionId,
        actor.organizationId,
        Buffer.alloc(32, 0x92),
        actor.memberId,
        actor.clientId,
        "https://boardagent.test"
      ]
    );
    const linked = await pool.query(
      "update access_token_records set session_id=$2 where id=$1 and session_id is null returning id",
      [actor.accessTokenRecordId, sessionId]
    );
    expect(linked.rowCount).toBe(1);
    // Real repository/page/cursor with real request authority; only expiry is
    // taken from the generated wire and independently constrained by wall time.
    const live = await transaction(async (client) => {
      const result = await client.query<{
        token_record_id: string;
        organization_id: string;
        member_id: string;
        internal_client_id: string;
        protocol_client_id: string;
        resource_uri: string;
        scope_set: string[];
        roles: string[];
        board_ids: string[];
      }>(
        "select token_record_id,organization_id,member_id,internal_client_id,protocol_client_id,resource_uri,scope_set,roles,board_ids from boardagent_resolve_access_token($1)",
        [actor.tokenJti]
      );
      expect(result.rows).toHaveLength(1);
      return result.rows[0]!;
    });
    expect(live).toMatchObject({
      token_record_id: actor.accessTokenRecordId,
      organization_id: actor.organizationId,
      member_id: actor.memberId,
      internal_client_id: actor.clientId
    });
    expect(live.resource_uri).toBe("https://boardagent.test/mcp");
    expect(live.scope_set).toEqual(
      expect.arrayContaining(["governance:read", "minutes:act", "secretariat:admin"])
    );
    expect(live.scope_set).toHaveLength(3);
    expect(live.board_ids).toEqual([actor.boardId]);
    const principal: SurfacePrincipal = {
      organizationId: live.organization_id,
      memberId: live.member_id,
      serviceOrigin: "https://boardagent.test",
      clientId: live.internal_client_id,
      protocolClientId: live.protocol_client_id,
      accessTokenRecordId: live.token_record_id,
      tokenJti: actor.tokenJti,
      keyId: "test-oauth",
      scopes: live.scope_set,
      roles: live.roles,
      boardIds: live.board_ids
    };
    const repository = new PgSurfaceReadRepository(pool, {
      cursorKey: minutesListCursorKey,
      transaction: { assumeRole: "boardagent_server" }
    });
    for (const kind of ["versions", "reviews"] as const) {
      let cursor: string | null = null,
        selection = input(kind, 1);
      const seen: string[] = [];
      for (let page = 0; page < 3; page++) {
        const old = await original(selection);
        expect(old).toHaveLength(page === 2 ? 1 : 2);
        const owner = manager.openRequest(new AbortController().signal);
        let actual,
          held = 0;
        const before = Math.floor(Date.now() / 1000);
        try {
          actual = await owner.produce(() =>
            repository.executeRead(principal, minutesListTools[kind], {
              schema_version: TOOL_INPUT_SCHEMA_VERSION,
              minutes_id: selection.minutesId,
              limit: 1,
              cursor
            })
          );
          held = manager.accounting.usedUnits;
        } finally {
          try {
            owner.nativeTerminal();
          } finally {
            owner.collectorSettled();
          }
        }
        const after = Math.floor(Date.now() / 1000),
          data = originalObject(actual.data),
          expected = originalListEnvelope(
            kind,
            selection.minutesId,
            old,
            1,
            principal,
            data["next_cursor"],
            before,
            after
          );
        expect(actual).toEqual(expected);
        expect(held).toBe(1);
        expect(manager.accounting.usedUnits).toBe(0);
        seen.push(old[0]!.cursor_id);
        cursor = typeof data["next_cursor"] === "string" ? data["next_cursor"] : null;
        selection = { ...selection, cursorAt: old[0]!.cursor_at, cursorId: old[0]!.cursor_id };
      }
      expect(seen).toEqual(
        (kind === "versions" ? allVersions : allReviews).old.map((row) => row.cursor_id)
      );
      expect(cursor).toBeNull();
      await verify(input(kind, 2));
      expect((await verify(selection)).old).toEqual([]);
    }

    // Constructor shape probes are test-local SQL copies. VOLATILE random()
    // forces runtime evaluation; no stored data, policies or functions change.
    let falseControls = 0,
      trueFaults = 0;
    const constructors = [
      { kind: "versions", needle: "jsonb_build_object('version_id',chosen.id" },
      { kind: "reviews", needle: "jsonb_build_object('review_item_id',chosen.id" },
      { kind: "reviews", needle: "jsonb_build_object('withdrawal_id',chosen.withdrawal_id" },
      { kind: "reviews", needle: "jsonb_build_object('disposition_id',chosen.disposition_id" }
    ] as const;
    for (const mode of ["force_custom_plan", "force_generic_plan"])
      for (const [index, probe] of constructors.entries()) {
        const selection = input(probe.kind),
          full = await metadata(selection);
        expect(full).toHaveLength(3);
        const sql = replaceOnce(
          MINUTES_LIST_CONTENT_SQL[probe.kind],
          probe.needle,
          `jsonb_build_object('fault',1/(0*random())) || ${probe.needle}`
        );
        const changedTime = await transaction(
          async (client) =>
            (
              await client.query<{ at: string }>(
                "select ($1::timestamptz+interval '1 microsecond')::text as at",
                [full[0]!.raw_created_at]
              )
            ).rows[0]!.at
        );
        const alterations: Partial<MinutesListMetadata>[] = [
          { id: testId(338001) },
          { raw_created_at: changedTime },
          { observation_sha256: "f".repeat(64) },
          { cursor_at: "synthetic-cursor-mismatch" },
          { withdrawal_count: String(1 - Number(full[0]!.withdrawal_count)) },
          { disposition_count: String(1 - Number(full[0]!.disposition_count)) },
          ...(["scalar_utf8", "json_utf8", "json_properties", "json_containers"] as const).map(
            (key) => ({ [key]: String(BigInt(full[0]![key]) - 1n) })
          )
        ];
        expect(alterations).toHaveLength(10);
        for (const delta of alterations) {
          const changed = full.map((row, i) => (i === 0 ? { ...row, ...delta } : row));
          const result = await admittedSql(
            selection,
            changed,
            sql,
            `ml_false_${mode}_${index}`,
            mode
          );
          expect(result.rows).toEqual([
            { fits: false, item: null, cursor_at: null, cursor_id: null }
          ]);
          falseControls++;
        }
        await expect(
          admittedSql(selection, full, sql, `ml_true_${mode}_${index}`, mode)
        ).rejects.toMatchObject({ code: "22012" });
        trueFaults++;
      }
    expect(falseControls).toBe(80);
    expect(trueFaults).toBe(8);

    // SQL-shape probes below retain the actual authorized rows and RLS. Strict
    // normal writers do not emit these malformed / unsafe-number JSON values.
    const offpage = allReviews.old[2]!.cursor_id;
    const malformed = `case when item.id='${offpage}'::uuid then convert_to('{"unterminated":','UTF8') else item.canonical_payload end`;
    const malformedTransform = (sql: string) =>
      replaceOnce(sql, "item.canonical_payload", `(${malformed})`);
    const small = input("reviews", 1),
      included = input("reviews", 2);
    expect(
      (await verify(small, malformedTransform, "item.exact_anchor", malformed)).old
    ).toHaveLength(2);
    await expect(original(included, malformedTransform)).rejects.toMatchObject({ code: "22P02" });
    await expect(read(included, undefined, malformedTransform)).rejects.toMatchObject({
      code: "22P02"
    });
    const anchor = "jsonb_set(item.exact_anchor,'{carry}','9999999999999999'::jsonb,true)";
    const carry = (sql: string) => replaceOnce(sql, "item.exact_anchor", anchor);
    const carryProof = await verify(input("reviews"), carry, anchor);
    const carryRows = carryProof.old.filter((row) => row.item["anchor"] !== null);
    expect(carryRows.length).toBeGreaterThan(0);
    for (const row of carryRows)
      expect(originalObject(row.item["anchor"])["carry"]).toBe(10000000000000000);
    const numericText = await transaction(
      async (client) =>
        (
          await client.query<{ text: string }>(
            `select (${anchor})::text as text from minutes_review_items as item where item.id=$1`,
            [reviews.redline]
          )
        ).rows[0]!.text
    );
    expect(numericText).toContain("9999999999999999");

    // Selective source omission is a query-shape control, not a claim that the
    // current RLS policy independently hides a review root or withdrawal row.
    const omit = allReviews.old[0]!.cursor_id;
    const omitTransform = (sql: string) =>
      replaceOnce(
        sql,
        "where item.minutes_id=$1",
        `where item.id<>'${omit}'::uuid and item.minutes_id=$1`
      );
    let omitActive = false;
    const freshOmit = (sql: string) => (omitActive ? omitTransform(sql) : sql);
    await expect(
      read(
        input("reviews", 1),
        async () => {
          omitActive = true;
        },
        freshOmit
      )
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const backfilled = await verify(input("reviews", 1), omitTransform);
    expect(backfilled.old.map((row) => row.cursor_id)).toEqual(
      allReviews.old.slice(1).map((row) => row.cursor_id)
    );
    omitActive = false;
    const subset = await read(
      input("reviews"),
      async () => {
        omitActive = true;
      },
      freshOmit
    );
    expect(strip(subset.rows)).toEqual(await original(input("reviews"), omitTransform));
    expect(subset.rows).toHaveLength(2);
    const hideWithdrawal = (sql: string) =>
      replaceOnce(
        sql,
        "withdrawal.review_item_id=item.id",
        "withdrawal.review_item_id=item.id and false"
      );
    let childHidden = false;
    const freshChild = (sql: string) => (childHidden ? hideWithdrawal(sql) : sql);
    await expect(
      read(
        input("reviews"),
        async () => {
          childHidden = true;
        },
        freshChild
      )
    ).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
    const noChild = await verify(input("reviews"), hideWithdrawal);
    expect(noChild.old.every((row) => row.item["withdrawal"] === null)).toBe(true);

    const occupied = manager.openRequest(new AbortController().signal),
      unit = responseAllocationPlan({
        kind: "document",
        representation: "tool",
        canonicalBytes: 1,
        sourceId: testId(338002),
        sourceVersion: "1",
        sha256: "a".repeat(64)
      });
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 2048; i++) occupied.reserve(unit);
      });
      await expect(read(input("reviews"))).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(reports.at(-1)).toMatchObject({
        preflights: 1,
        contents: 0,
        held: 2048,
        finalUnits: 2048
      });
    } finally {
      try {
        occupied.nativeTerminal();
      } finally {
        occupied.collectorSettled();
      }
    }
    for (const kind of ["versions", "reviews"] as const)
      for (const context of [
        { ...actor.context, organizationId: testId(338003) },
        { ...actor.context, boardIds: [] }
      ]) {
        expect(await original(input(kind), identity, context)).toEqual([]);
        const hidden = await read(input(kind), undefined, identity, context);
        expect(hidden.rows).toEqual([]);
        expect(hidden.held).toBe(1);
      }
    const hidden = await read(input("reviews"), () =>
      excludeMinutesLineageEndpoint(pool, actor, fixture.replacementId, 338100)
    );
    expect(hidden.rows).toEqual([]);
    expect(hidden.held).toBe(1);
    for (const kind of ["versions", "reviews"] as const) {
      expect(await original(input(kind))).toEqual([]);
      expect((await read(input(kind))).rows).toEqual([]);
    }
    expect(manager.accounting.usedUnits).toBe(0);
    console.info(
      JSON.stringify({
        probe: "minutes-lists-projection",
        catalog,
        normalMinutesCommands: fixture.commands,
        falseControls,
        trueFaults,
        contentHashes,
        numericText,
        lookaheadPages: 6,
        syntheticVariants: [
          "malformed offpage/included",
          "JSON numeric carry",
          "selective frontier backfill/subset",
          "withdrawal visibility"
        ],
        actualAuthority:
          "boardagent_server request scope; wrong org/board and constrained minutes recusal",
        reports,
        finalUnits: manager.accounting.usedUnits,
        nativeLifetime: "modeled owner terminal/collector markers only; native test is separate"
      })
    );
  });
}, 90000);
