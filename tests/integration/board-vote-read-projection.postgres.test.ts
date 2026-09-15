import type { Pool, PoolClient } from "pg";
import { expect, it } from "vitest";
import { canonicalJson, type JsonValue } from "../../lib/contracts/src/canonical.js";
import {
  grantProxyInTransaction,
  revokeProxyInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import {
  BOARD_VOTE_PAGE_PREFLIGHT_SQL,
  BOARD_VOTE_PAGE_CONTENT_SQL,
  PROXY_STATUS_PREFLIGHT_SQL,
  PROXY_STATUS_CONTENT_SQL,
  VOTE_LINEAGE_PREFLIGHT_SQL,
  VOTE_LINEAGE_CONTENT_SQL,
  boardVotePageCost,
  boardVotePagePlan,
  proxyStatusCost,
  proxyStatusPlan,
  voteLineageCost,
  voteLineagePlan,
  loadAdmittedBoardVotePage,
  loadAdmittedProxyStatus,
  loadAdmittedVoteLineage,
  type BoardVotePageMetadata,
  type ProxyStatusMetadata,
  type VoteLineageMetadata
} from "../../artifacts/server/src/board-vote-read-projection.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  seedVoteToolBallotFixture,
  seedBoardVoteReplacementFixture,
  confirmedVoteToolProxyGrantInput,
  confirmedBoardVoteProxyRevokeInput
} from "../helpers/vote-tool-ballot-fixture.js";
import {
  originalBoardVotePage,
  originalProxyStatus,
  originalVoteLineage,
  boardVoteGraph,
  boardVoteObject,
  BOARD_KEYS,
  VOTE_KEYS,
  GRANT_FLAT_KEYS,
  REVOCATION_KEYS,
  LINEAGE_FLAT_KEYS
} from "../helpers/board-vote-postgres-oracle.js";

type Context = Parameters<typeof withRequestTransaction>[1];
type Route =
  | {
      kind: "boards" | "votes";
      selector: string;
      at: string | null;
      cursor: string | null;
      take: number;
    }
  | { kind: "proxy"; vote: string; member: string; principal: string }
  | { kind: "lineage"; vote: string };
type Metadata =
  readonly BoardVotePageMetadata[] | ProxyStatusMetadata | readonly VoteLineageMetadata[];
const sql = (route: Route) =>
  route.kind === "proxy"
    ? [PROXY_STATUS_PREFLIGHT_SQL, PROXY_STATUS_CONTENT_SQL]
    : route.kind === "lineage"
      ? [VOTE_LINEAGE_PREFLIGHT_SQL, VOTE_LINEAGE_CONTENT_SQL]
      : [BOARD_VOTE_PAGE_PREFLIGHT_SQL[route.kind], BOARD_VOTE_PAGE_CONTENT_SQL[route.kind]];
const parameters = (route: Route): unknown[] =>
  route.kind === "proxy"
    ? [route.vote, route.member, route.principal]
    : route.kind === "lineage"
      ? [route.vote]
      : [route.selector, route.at, route.cursor, route.take];
const pageInput = (route: Extract<Route, { kind: "boards" | "votes" }>) => ({
  kind: route.kind,
  selectorId: route.selector,
  at: route.at,
  cursorId: route.cursor,
  take: route.take
});
const plan = (route: Route, metadata: Metadata) =>
  route.kind === "proxy"
    ? proxyStatusPlan(metadata as ProxyStatusMetadata)
    : route.kind === "lineage"
      ? voteLineagePlan(route.vote, metadata as readonly VoteLineageMetadata[])
      : boardVotePagePlan(pageInput(route), metadata as readonly BoardVotePageMetadata[]);
const cost = (route: Route, metadata: Metadata) =>
  route.kind === "proxy"
    ? proxyStatusCost(metadata as ProxyStatusMetadata)
    : route.kind === "lineage"
      ? voteLineageCost(metadata as readonly VoteLineageMetadata[])
      : boardVotePageCost(route.kind, metadata as readonly BoardVotePageMetadata[]);
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const close = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
const transact = <T>(pool: Pool, context: Context, work: (client: PoolClient) => Promise<T>) =>
  withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
const observations: Record<string, unknown>[] = [];
async function original(client: PoolClient, route: Route) {
  if (route.kind === "proxy") {
    const read = await originalProxyStatus(client, route.vote, route.member, route.principal);
    return { value: read.items, metadata: read.metadata };
  }
  if (route.kind === "lineage") {
    const read = await originalVoteLineage(client, route.vote);
    return { value: read.items, metadata: read.metadata };
  }
  const read = await originalBoardVotePage(client, route.kind, parameters(route));
  return { value: read.rows, metadata: read.metadata };
}
async function read(
  pool: Pool,
  context: Context,
  route: Route,
  options: {
    manager?: ResponseAllocationManager;
    afterMetadata?: () => Promise<void>;
    abortAfterMetadata?: boolean;
    afterContent?: (client: PoolClient) => Promise<void>;
  } = {}
) {
  const manager = options.manager ?? new ResponseAllocationManager(),
    initial = manager.accounting.usedUnits,
    abort = new AbortController(),
    owner = manager.openRequest(abort.signal),
    names = sql(route);
  let metadataCalls = 0,
    contentCalls = 0,
    metadata: Metadata | undefined,
    retained: unknown = [],
    value: unknown,
    error: unknown,
    held = 0;
  try {
    value = await owner.produce(() =>
      transact(pool, context, async (client) => {
        const port = {
          query: async (text: string, values?: unknown[]) => {
            if (text === names[1]) contentCalls += 1;
            const result = await client.query(text, values);
            if (text === names[0]) {
              metadataCalls += 1;
              metadata =
                route.kind === "proxy" ? (result.rows[0] as ProxyStatusMetadata) : result.rows;
              await options.afterMetadata?.();
              if (options.abortAfterMetadata) abort.abort();
            }
            if (text === names[1]) retained = result.rows;
            return result;
          }
        } as unknown as PoolClient;
        let result: unknown, failure: unknown;
        try {
          result =
            route.kind === "proxy"
              ? await loadAdmittedProxyStatus(port, route.vote, route.member, route.principal)
              : route.kind === "lineage"
                ? await loadAdmittedVoteLineage(port, route.vote)
                : await loadAdmittedBoardVotePage(port, pageInput(route));
        } catch (caught) {
          failure = caught;
        }
        try {
          await options.afterContent?.(client);
        } catch (caught) {
          if (failure !== undefined)
            throw new AggregateError(
              [failure, caught],
              "board/vote query and after-content oracle failed"
            );
          throw caught;
        }
        if (failure !== undefined) throw failure;
        return result;
      })
    );
  } catch (caught) {
    error = caught;
  } finally {
    held = manager.accounting.usedUnits - initial;
    close(owner);
  }
  if (manager.accounting.usedUnits !== initial)
    throw new AggregateError(error === undefined ? [] : [error], "board/vote owner did not settle");
  return { value, error, metadata, retained, metadataCalls, contentCalls, held };
}
function envelope(route: Route, value: unknown) {
  const tool =
    route.kind === "boards"
      ? "list_my_boards"
      : route.kind === "votes"
        ? "list_votes"
        : route.kind === "proxy"
          ? "get_proxy_status"
          : "get_vote_lineage";
  const data =
    route.kind === "proxy"
      ? { vote_id: route.vote, member_id: route.member, grants: value }
      : route.kind === "lineage"
        ? { vote_id: route.vote, lineage: value }
        : { items: (value as { item: JsonValue }[]).map((row) => row.item), next_cursor: null };
  return {
    schema_version: "boardagent.tool-result.v1",
    tool,
    status: "ok",
    reference: route.kind === "proxy" || route.kind === "lineage" ? route.vote : null,
    resource_uri: null,
    data
  };
}
async function verify(pool: Pool, context: Context, route: Route) {
  const expected = await transact(pool, context, (client) => original(client, route)); // Before any occupancy.
  const actual = await read(pool, context, route);
  if (actual.error !== undefined) throw actual.error;
  expect(actual.metadataCalls).toBe(1);
  expect(actual.contentCalls).toBe(1);
  expect(actual.metadata).toEqual(expected.metadata);
  const value =
    route.kind === "boards" || route.kind === "votes"
      ? (actual.value as Array<Record<string, unknown>>).map(({ item, cursor_at, cursor_id }) => ({
          item,
          cursor_at,
          cursor_id
        }))
      : actual.value;
  expect(canonicalJson(value)).toBe(canonicalJson(expected.value));
  const payload = envelope(route, value),
    wire = {
      content: [{ type: "text", text: JSON.stringify(payload) }],
      structuredContent: payload
    };
  const admitted = plan(route, expected.metadata),
    metrics = cost(route, expected.metadata),
    shape = boardVoteGraph([wire, actual.retained]);
  expect(actual.held).toBe(admitted.units);
  expect(Buffer.byteLength(JSON.stringify(actual.retained))).toBeLessThanOrEqual(
    Number(metrics.jsonUpperBytes)
  );
  expect(BigInt(shape.properties)).toBeLessThanOrEqual(BigInt(metrics.propertyCount));
  expect(BigInt(shape.containers)).toBeLessThanOrEqual(BigInt(metrics.objectOrArrayCount));
  expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(admitted.wireUpperBytes);
  observations.push({
    kind: route.kind,
    rows:
      route.kind === "proxy"
        ? (expected.metadata as ProxyStatusMetadata).grant_count
        : (expected.metadata as readonly unknown[]).length,
    metadata: expected.metadata,
    metrics,
    canonicalBytes: Buffer.byteLength(canonicalJson(payload)),
    wireBytes: Buffer.byteLength(JSON.stringify(wire)),
    held: actual.held
  });
  return { expected, actual };
}
function inject(text: string, needle: string, replacement: string) {
  expect(text.split(needle)).toHaveLength(2);
  return text.replace(needle, replacement);
}
let falseGates = 0,
  trueFaults = 0;
async function faults(pool: Pool, context: Context, route: Route, metadata: Metadata) {
  const originalText = sql(route)[1]!;
  const variants =
    route.kind === "proxy"
      ? [
          [
            "grant",
            "'grant_id',source.grant_id",
            "'grant_id',source.grant_id::text||(1/(length(source.grant_id::text)-36))::text"
          ],
          [
            "revocation",
            "'revocation_id',source.revocation_id",
            "'revocation_id',source.revocation_id::text||(1/(length(source.revocation_id::text)-36))::text"
          ]
        ]
      : route.kind === "lineage"
        ? [
            [
              "edge",
              "'supersession_id',source.supersession_id",
              "'supersession_id',source.supersession_id::text||(1/(length(source.supersession_id::text)-36))::text"
            ]
          ]
        : [
            [
              "wrapper",
              "'fits',true,'item'",
              "'fits',(1/(length(source.row_id::text)-36)=0),'item'"
            ],
            [
              "item",
              route.kind === "boards" ? "'board_id',source.row_id" : "'vote_id',source.row_id",
              (route.kind === "boards" ? "'board_id'" : "'vote_id'") +
                ",source.row_id::text||(1/(length(source.row_id::text)-36))::text"
            ]
          ];
  const bound = clone(metadata),
    falseBounds: { name: string; value: Metadata }[] = [];
  if (route.kind === "proxy") {
    for (const key of [
      "grant_count",
      "revocation_count",
      "scalar_utf8",
      "observation_sha256"
    ] as const) {
      const changed = clone(bound as ProxyStatusMetadata);
      falseBounds.push({
        name: key,
        value: {
          ...changed,
          [key]: key === "observation_sha256" ? "0".repeat(64) : String(BigInt(changed[key]) - 1n)
        }
      });
    }
  } else {
    const rows = bound as unknown as readonly Record<string, string | null>[];
    expect(rows.length).toBeGreaterThan(0);
    const keys =
      route.kind === "lineage"
        ? [
            "supersession_id",
            "old_vote_id",
            "new_vote_id",
            "raw_at",
            "scalar_utf8",
            "json_utf8",
            "json_containers",
            "observation_sha256"
          ]
        : [
            "id",
            "join_id",
            "outcome_id",
            "raw_at",
            "cursor_at",
            "cursor_id",
            "scalar_utf8",
            "observation_sha256"
          ];
    const changedTime = await transact(
      pool,
      context,
      async (client) =>
        (
          await client.query<{ value: string }>(
            "select ($1::timestamptz+interval '1 microsecond')::text as value",
            [rows[0]!.raw_at]
          )
        ).rows[0]!.value
    );
    for (const key of keys) {
      const changed = clone(rows) as Record<string, string | null>[];
      changed[0]![key] =
        key === "observation_sha256"
          ? "0".repeat(64)
          : key === "raw_at"
            ? changedTime
            : key === "cursor_at"
              ? "different"
              : ["scalar_utf8", "json_utf8", "json_containers"].includes(key)
                ? String(BigInt(changed[0]![key]!) - 1n)
                : testId(290999);
      falseBounds.push({ name: key, value: changed as unknown as Metadata });
    }
    falseBounds.push({ name: "count", value: [] });
  }
  const args = (value: Metadata) =>
    route.kind === "proxy"
      ? [
          ...parameters(route),
          ...["grant_count", "revocation_count", "scalar_utf8", "observation_sha256"].map(
            (key) => (value as unknown as Record<string, string>)[key]
          )
        ]
      : [...parameters(route), JSON.stringify(value)];
  for (const mode of ["force_custom_plan", "force_generic_plan"] as const)
    for (const [label, needle, replacement] of variants) {
      const text = inject(originalText, needle!, replacement!),
        name = `bv_${route.kind}_${label}_${mode}`;
      for (const control of falseBounds) {
        const rows = await transact(pool, context, async (client) => {
          await client.query(`set local plan_cache_mode=${mode}`);
          return (await client.query({ name, text, values: args(control.value) })).rows;
        });
        expect(rows).toHaveLength(1);
        expect(rows[0].fits).toBe(false);
        expect(
          route.kind === "proxy" || route.kind === "lineage" ? rows[0].items : rows[0].item
        ).toBeNull();
        falseGates += 1;
      }
      await expect(
        transact(pool, context, async (client) => {
          await client.query(`set local plan_cache_mode=${mode}`);
          await client.query({ name, text, values: args(bound) });
        })
      ).rejects.toMatchObject({ code: "22012" });
      trueFaults += 1;
    }
}
async function saturate(pool: Pool, context: Context, route: Route) {
  const manager = new ResponseAllocationManager(),
    occupied = manager.openRequest(new AbortController().signal);
  const small = responseAllocationPlan({
    kind: "document",
    representation: "tool",
    canonicalBytes: 1,
    sourceId: "bv-small",
    sourceVersion: "1",
    sha256: "a".repeat(64)
  });
  try {
    await occupied.produce(async () => {
      for (let index = 0; index < 2048; index++) occupied.reserve(small);
    });
    const result = await read(pool, context, route, { manager });
    expect(result.error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(result.metadataCalls).toBe(1);
    expect(result.contentCalls).toBe(0);
    expect(result.held).toBe(0);
    expect(manager.accounting.usedUnits).toBe(2048);
  } finally {
    close(occupied);
  }
  expect(manager.accounting.usedUnits).toBe(0);
}
async function wrongContexts(pool: Pool, context: Context, route: Route) {
  for (const [name, different] of [
    ["wrong-organization", { ...context, organizationId: testId(290997) }],
    ["empty-board-context", { ...context, boardIds: [] }]
  ] as const) {
    const expected = await transact(pool, different, (client) => original(client, route));
    const result = await read(pool, different, route);
    if (result.error !== undefined) throw result.error;
    const value =
      route.kind === "boards" || route.kind === "votes"
        ? (result.value as Array<Record<string, unknown>>).map(
            ({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id })
          )
        : result.value;
    expect(canonicalJson(value)).toBe(canonicalJson(expected.value));
    observations.push({
      kind: route.kind,
      context: name,
      originalRows: (expected.value as unknown[]).length
    });
  }
}

it("admits four original board vote views before full constructors and binds actual normal proxy and lineage changes", async () => {
  await withMigratedDatabase("bv_projection_proxy", async (pool) => {
    const fixture = await seedVoteToolBallotFixture(pool),
      context = fixture.actorB.context;
    const route: Route = {
      kind: "proxy",
      vote: fixture.voteId,
      member: fixture.actorB.memberId,
      principal: fixture.actorB.memberId
    };
    await verify(pool, context, route);
    const grant = await confirmedVoteToolProxyGrantInput(pool, fixture, {
      actor: fixture.actorB,
      holderMemberId: fixture.actorA.memberId,
      idBase: 280000
    });
    await transact(pool, context, (client) => grantProxyInTransaction(client, grant));
    await verify(pool, context, route);
    const revoke = await confirmedBoardVoteProxyRevokeInput(pool, fixture, {
      actor: fixture.actorB,
      proxyGrantId: grant.proxyGrantId,
      idBase: 281000
    });
    const changed = await read(pool, context, route, {
      afterMetadata: () =>
        transact(pool, context, (client) => revokeProxyInTransaction(client, revoke)).then(
          () => undefined
        )
    });
    expect(changed.error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(changed.contentCalls).toBe(1);
    expect(changed.held).toBeGreaterThan(0);
    const current = await verify(pool, context, route);
    const item = boardVoteObject((current.expected.value as JsonValue[])[0]);
    expect(Object.keys(item).sort()).toEqual([...GRANT_FLAT_KEYS, "revocation"].sort());
    expect(Object.keys(boardVoteObject(item.revocation)).sort()).toEqual(
      [...REVOCATION_KEYS].sort()
    );
    await faults(pool, context, route, current.expected.metadata);
    await saturate(pool, context, route);
    await wrongContexts(pool, context, route);
    const disconnected = await read(pool, context, route, { abortAfterMetadata: true });
    expect(disconnected.error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(disconnected.contentCalls).toBe(0);
    let fresh: unknown;
    const revoked = await read(pool, context, route, {
      afterMetadata: async () => {
        const result = await pool.query(
          "update access_token_records set revoked_at=clock_timestamp() where organization_id=$1 and jti=$2 and revoked_at is null",
          [context.organizationId, context.tokenJti]
        );
        expect(result.rowCount).toBe(1);
      },
      afterContent: async (client) => {
        fresh = (await original(client, route)).value;
      }
    });
    if (revoked.error !== undefined) throw revoked.error;
    expect(canonicalJson(revoked.value)).toBe(canonicalJson(fresh));
    observations.push({
      kind: "proxy",
      tokenRevokedBetweenStatements: true,
      originalRows: (fresh as unknown[]).length,
      returnedRows: (revoked.value as unknown[]).length,
      held: revoked.held
    });
  });
  await withMigratedDatabase("bv_projection_lineage", async (pool) => {
    const fixture = await seedBoardVoteReplacementFixture(pool),
      context = fixture.context;
    const boards: Route = {
      kind: "boards",
      selector: fixture.actorA.memberId,
      at: null,
      cursor: null,
      take: 101
    };
    const votes: Route = {
      kind: "votes",
      selector: fixture.boardId,
      at: null,
      cursor: null,
      take: 101
    };
    const lineage: Route = { kind: "lineage", vote: fixture.middleVoteId };
    const catalog = await transact(
      pool,
      context,
      async (client) =>
        (
          await client.query(
            `select class.relname,class.relrowsecurity,class.relforcerowsecurity,
      exists(select 1 from pg_index as idx where idx.indrelid=class.oid and idx.indisprimary and idx.indisvalid) as primary_key
      from pg_class as class join pg_namespace as ns on ns.oid=class.relnamespace where ns.nspname='public'
      and class.relname=any($1::text[]) order by class.relname`,
            [
              [
                "boards",
                "board_memberships",
                "votes",
                "vote_outcomes",
                "decision_packages",
                "proxy_grants",
                "proxy_revocations",
                "vote_supersessions"
              ]
            ]
          )
        ).rows
    );
    expect(catalog).toHaveLength(8);
    for (const table of catalog)
      expect(table).toMatchObject({
        relrowsecurity: true,
        relforcerowsecurity: true,
        primary_key: true
      });
    const unique = await transact(
      pool,
      context,
      async (client) =>
        (
          await client.query(`select class.relname,att.attname from pg_index as idx join pg_class as class on class.oid=idx.indrelid
      join pg_namespace as ns on ns.oid=class.relnamespace join pg_attribute as att on att.attrelid=class.oid and att.attnum=idx.indkey[0]
      where ns.nspname='public' and idx.indisunique and idx.indisvalid and idx.indnkeyatts=1 and idx.indpred is null
      and ((class.relname='vote_supersessions' and att.attname in ('old_vote_id','new_vote_id')) or (class.relname='proxy_revocations' and att.attname='grant_id') or (class.relname='vote_outcomes' and att.attname='vote_id')) order by class.relname,att.attname`)
        ).rows
    );
    expect(unique).toEqual([
      { relname: "proxy_revocations", attname: "grant_id" },
      { relname: "vote_outcomes", attname: "vote_id" },
      { relname: "vote_supersessions", attname: "new_vote_id" },
      { relname: "vote_supersessions", attname: "old_vote_id" }
    ]);
    observations.push({ catalog, unique, membershipPartialUniquenessNotAssumed: true });
    await verify(pool, context, boards);
    await verify(pool, context, votes);
    await verify(pool, context, { kind: "lineage", vote: fixture.originalVoteId });
    const newRoot = await read(pool, context, votes, {
      afterMetadata: () => fixture.replaceOnce().then(() => undefined)
    });
    expect(newRoot.error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(newRoot.contentCalls).toBe(1);
    await verify(pool, context, lineage);
    const newEdge = await read(pool, context, lineage, {
      afterMetadata: () => fixture.appendSuccessor().then(() => undefined)
    });
    expect(newEdge.error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(newEdge.contentCalls).toBe(1);
    for (const route of [boards, votes, lineage]) {
      const current = await verify(pool, context, route);
      await faults(pool, context, route, current.expected.metadata);
      await saturate(pool, context, route);
      await wrongContexts(pool, context, route);
      const rows = current.expected.value as Array<Record<string, JsonValue>>;
      for (const row of rows)
        expect(
          Object.keys(route.kind === "lineage" ? row : boardVoteObject(row.item)).sort()
        ).toEqual(
          [
            ...(route.kind === "boards"
              ? BOARD_KEYS
              : route.kind === "votes"
                ? VOTE_KEYS
                : [...LINEAGE_FLAT_KEYS, "changed_component_classes"])
          ].sort()
        );
    }
    const first = await verify(pool, context, { ...votes, take: 2 }),
      firstRows = first.expected.value as Array<{ cursor_at: string; cursor_id: string }>;
    expect(firstRows).toHaveLength(2);
    const next = await verify(pool, context, {
      ...votes,
      at: firstRows[0]!.cursor_at,
      cursor: firstRows[0]!.cursor_id,
      take: 2
    });
    const last = (next.expected.value as Array<{ cursor_at: string; cursor_id: string }>).at(-1)!;
    expect(next.expected.value).toHaveLength(2);
    expect(
      (await verify(pool, context, { ...votes, at: last.cursor_at, cursor: last.cursor_id }))
        .expected.value
    ).toEqual([]);
  });
  expect(falseGates).toBe(106);
  expect(trueFaults).toBe(14);
  process.stdout.write(
    `BOARD_VOTE_PROJECTION_OBSERVATION ${JSON.stringify({
      falseGates,
      trueFaults,
      observations,
      limitations: [
        "Direct actual-role helpers; public SDK calls are a separate native case",
        "No 500-row PG or joined-membership tie fixture",
        "No new endpoint-recusal mutation; existing predicates preserved",
        "Token result is the observed same installed-context policy, not a new revoked public request"
      ]
    })}\n`
  );
}, 90_000);
