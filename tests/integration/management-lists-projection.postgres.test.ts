import type { Pool, PoolClient } from "pg";
import { expect, it } from "vitest";
import {
  canonicalJson,
  TOOL_INPUT_SCHEMA_VERSION,
  type JsonValue
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  SUBMISSION_LIST_PREFLIGHT_SQL,
  SUBMISSION_LIST_CONTENT_SQL,
  loadAdmittedSubmissionList,
  submissionListProjectionPlan,
  submissionListProjectionCost,
  type SubmissionListMetadata
} from "../../artifacts/server/src/management-submission-list-projection.js";
import {
  loadAdmittedQuestionList,
  questionListProjectionCost,
  questionListProjectionPlan
} from "../../artifacts/server/src/management-question-list-projection.js";
import {
  QUESTION_LIST_PROJECTION_PREFLIGHT_SQL,
  QUESTION_LIST_PROJECTION_CONTENT_SQL
} from "../../lib/db/src/question-queries.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  seedManagementProjectionFixture,
  type ManagementProjectionFixture
} from "../helpers/management-projection-fixture.js";
import {
  originalManagementSubmissionList,
  originalManagementQuestionList,
  managementGraph,
  managementObject,
  SUBMISSION_LIST_KEYS,
  QUESTION_LIST_FLAT
} from "../helpers/management-postgres-oracle.js";
import {
  ORIGINAL_SUBMISSION_LIST_SQL,
  ORIGINAL_QUESTION_LIST_SQL
} from "../helpers/management-read-original-sql.js";
import {
  managementListCursorKey,
  managementListTools,
  signManagementListTailCursor,
  originalManagementListEnvelope,
  type OriginalManagementPageRow,
  type ManagementListKind
} from "../helpers/management-page-oracle.js";

type Route = { kind: ManagementListKind; limit: number; at: string | null; id: string | null };
type Context = Parameters<typeof withRequestTransaction>[1];
type Metadata = Record<string, string | null>;
const transaction = <T>(pool: Pool, context: Context, work: (client: PoolClient) => Promise<T>) =>
  withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
const close = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
const actorName = (route: Route) => (route.kind === "submissions" ? "secretary" : "asker");
const names = (route: Route) =>
  route.kind === "submissions"
    ? [SUBMISSION_LIST_PREFLIGHT_SQL, SUBMISSION_LIST_CONTENT_SQL]
    : [QUESTION_LIST_PROJECTION_PREFLIGHT_SQL, QUESTION_LIST_PROJECTION_CONTENT_SQL];
const parameters = (fixture: ManagementProjectionFixture, route: Route) => [
  fixture.boardId,
  route.kind === "submissions" ? fixture.actors.secretary.memberId : null,
  route.at,
  route.id,
  route.limit + 1
];
const submissionInput = (fixture: ManagementProjectionFixture, route: Route) => ({
  boardId: fixture.boardId,
  memberId: fixture.actors.secretary.memberId,
  limit: route.limit,
  cursorAt: route.at,
  cursorId: route.id
});
const questionInput = (fixture: ManagementProjectionFixture, route: Route) => ({
  boardId: fixture.boardId,
  limit: route.limit,
  ...(route.at === null ? {} : { after: { createdAt: route.at, questionId: route.id! } })
});
function questionRows(items: readonly JsonValue[]): OriginalManagementPageRow[] {
  return items.map((item) => {
    const value = managementObject(item);
    return {
      item,
      cursor_at: value.createdAt === null ? null : String(value.createdAt),
      cursor_id: String(value.questionId)
    };
  });
}
function sums(rows: readonly SubmissionListMetadata[]) {
  const sum = (
    key: "scalar_utf8" | "normalized_json_utf8" | "json_property_count" | "json_container_count"
  ) => rows.reduce((n, row) => n + BigInt(row[key]), 0n).toString();
  return {
    row_count: String(rows.length),
    scalar_utf8: sum("scalar_utf8"),
    normalized_json_utf8: sum("normalized_json_utf8"),
    json_property_count: sum("json_property_count"),
    json_container_count: sum("json_container_count")
  };
}
async function oracle(
  pool: Pool,
  fixture: ManagementProjectionFixture,
  route: Route,
  context = fixture.actors[actorName(route)].context,
  originalSql?: string
) {
  return transaction(pool, context, async (client) => {
    if (route.kind === "submissions") {
      const expected = await originalManagementSubmissionList(
        client,
        parameters(fixture, route),
        originalSql
      );
      return {
        value: expected.value,
        rows: expected.value,
        preflight: expected.metadata,
        bound: expected.metadata,
        plan: submissionListProjectionPlan(submissionInput(fixture, route), expected.metadata),
        metrics: submissionListProjectionCost(sums(expected.metadata)),
        totalVisible: undefined,
        normalized: expected.normalizedOwners
      };
    }
    const expected = await originalManagementQuestionList(
        client,
        parameters(fixture, route),
        originalSql
      ),
      rows = questionRows(expected.value.items),
      selected = expected.value.items.slice(0, route.limit),
      last = selected.at(-1),
      more = expected.value.items.length > route.limit;
    return {
      value: {
        items: selected,
        totalVisible: Number(expected.value.total_visible),
        nextCursor:
          more && last
            ? {
                createdAt: managementObject(last).createdAt,
                questionId: managementObject(last).questionId
              }
            : null
      },
      rows,
      preflight: expected.preflight,
      bound: expected.metadata,
      plan: questionListProjectionPlan(questionInput(fixture, route), expected.observation),
      metrics: questionListProjectionCost(expected.observation),
      totalVisible: expected.value.total_visible,
      normalized: expected.normalizedOwners
    };
  });
}
async function read(
  pool: Pool,
  fixture: ManagementProjectionFixture,
  route: Route,
  options: {
    manager?: ResponseAllocationManager;
    context?: Context;
    afterMetadata?: () => Promise<void>;
    abortAfterMetadata?: boolean;
    transformSql?: (sql: string) => string;
  } = {}
) {
  const manager = options.manager ?? new ResponseAllocationManager(),
    start = manager.accounting.usedUnits,
    abort = new AbortController(),
    owner = manager.openRequest(abort.signal),
    sqlNames = names(route);
  let value: unknown,
    error: unknown,
    metadata: unknown[] = [],
    retained: unknown[] = [],
    metadataCalls = 0,
    contentCalls = 0,
    held = 0;
  try {
    value = await owner.produce(() =>
      transaction(
        pool,
        options.context ?? fixture.actors[actorName(route)].context,
        async (client) => {
          const port = {
            query: async (sql: string, args: unknown[]) => {
              if (sql === sqlNames[1]) contentCalls += 1;
              const selected = sql === sqlNames[0] || sql === sqlNames[1];
              const result = await client.query(
                selected && options.transformSql ? options.transformSql(sql) : sql,
                args
              );
              if (sql === sqlNames[0]) {
                metadataCalls += 1;
                metadata = result.rows;
                await options.afterMetadata?.();
                if (options.abortAfterMetadata) abort.abort();
              }
              if (sql === sqlNames[1]) retained = result.rows;
              return result;
            }
          } as unknown as PoolClient;
          return route.kind === "submissions"
            ? loadAdmittedSubmissionList(port, submissionInput(fixture, route))
            : loadAdmittedQuestionList(port, questionInput(fixture, route));
        }
      )
    );
  } catch (caught) {
    error = caught;
  } finally {
    held = manager.accounting.usedUnits - start;
    close(owner);
  }
  if (manager.accounting.usedUnits !== start)
    throw new AggregateError(
      error === undefined ? [] : [error],
      "management list owner did not settle"
    );
  return { value, error, metadata, retained, metadataCalls, contentCalls, held };
}
async function verify(
  pool: Pool,
  fixture: ManagementProjectionFixture,
  route: Route,
  options: { context?: Context; originalSql?: string; transformSql?: (sql: string) => string } = {}
) {
  const expected = await oracle(
      pool,
      fixture,
      route,
      options.context ?? fixture.actors[actorName(route)].context,
      options.originalSql
    ),
    actual = await read(pool, fixture, route, options);
  if (actual.error !== undefined) throw actual.error;
  expect(actual.metadataCalls).toBe(1);
  expect(actual.contentCalls).toBe(1);
  expect(actual.metadata).toEqual(expected.preflight);
  const compared =
    route.kind === "submissions"
      ? (
          actual.value as Array<{ item: JsonValue; cursor_at: string | null; cursor_id: string }>
        ).map(({ item, cursor_at, cursor_id }) => ({ item, cursor_at, cursor_id }))
      : actual.value;
  expect(canonicalJson(compared)).toBe(canonicalJson(expected.value));
  expect(actual.held).toBe(expected.plan.units);
  expect(Buffer.byteLength(JSON.stringify(actual.retained))).toBeLessThanOrEqual(
    Number(expected.metrics.jsonUpperBytes)
  );
  // Direct question DB result and a separately parsed public item graph can coexist.
  const plain =
    route.kind === "questions"
      ? (JSON.parse(JSON.stringify((actual.value as { items: unknown }).items)) as JsonValue)
      : (actual.value as Array<{ item: JsonValue }>).slice(0, route.limit).map((row) => row.item);
  const envelope = {
    schema_version: "boardagent.tool-result.v1",
    tool: managementListTools[route.kind],
    status: "ok",
    reference: null,
    resource_uri: null,
    data: {
      items: plain,
      ...(route.kind === "questions" ? { total_visible: Number(expected.totalVisible) } : {}),
      next_cursor: null
    }
  };
  const wire = {
      content: [{ type: "text", text: JSON.stringify(envelope) }],
      structuredContent: envelope
    },
    graph = managementGraph([wire, actual.retained, actual.value]);
  expect(BigInt(graph.properties)).toBeLessThanOrEqual(BigInt(expected.metrics.propertyCount));
  expect(BigInt(graph.containers)).toBeLessThanOrEqual(BigInt(expected.metrics.objectOrArrayCount));
  expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(expected.plan.wireUpperBytes);
  return { expected, actual };
}
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
async function faults(
  pool: Pool,
  fixture: ManagementProjectionFixture,
  route: Route,
  rows: readonly Metadata[]
) {
  expect(rows.length).toBeGreaterThan(0);
  const isSubmission = route.kind === "submissions",
    fields = isSubmission
      ? [
          "id",
          "raw_order_key",
          "cursor_at",
          "observation_sha256",
          "scalar_utf8",
          "normalized_json_utf8",
          "json_property_count",
          "json_container_count"
        ]
      : [
          "question_id",
          "raw_created_at",
          "created_at",
          "observation_sha256",
          "scalar_utf8",
          "json_utf8",
          "json_properties",
          "json_containers"
        ];
  const source = names(route)[1]!,
    needle = isSubmission ? "'submission_id',chosen.id" : "'questionId',page.question_id",
    column = isSubmission ? "chosen.id" : "page.question_id";
  expect(source.split(needle)).toHaveLength(2);
  const text = source.replace(needle, `${needle}::text||(1/(length(${column}::text)-36))::text`);
  const bounds: Array<{ name: string; rows: readonly Metadata[] }> = [
    { name: "missing-frontier", rows: [] }
  ];
  const rawKey = isSubmission ? "raw_order_key" : "raw_created_at";
  const changedTime = await transaction(
    pool,
    fixture.actors[actorName(route)].context,
    async (client) =>
      (
        await client.query<{ value: string }>(
          "select ($1::timestamptz+interval '1 microsecond')::text as value",
          [rows[0]![rawKey]]
        )
      ).rows[0]!.value
  );
  for (const key of fields) {
    const changed = clone(rows) as Metadata[];
    changed[0]![key] =
      key === rawKey
        ? changedTime
        : key === "observation_sha256"
          ? "0".repeat(64)
          : key === "cursor_at" || key === "created_at"
            ? "different"
            : key === "id" || key === "question_id"
              ? testId(480_996)
              : String(
                  BigInt(changed[0]![key]!) +
                    (key.includes("propert") || key.includes("container") ? 1n : -1n)
                );
    bounds.push({ name: key, rows: changed });
  }
  let falseGates = 0,
    trueFaults = 0;
  for (const mode of ["force_custom_plan", "force_generic_plan"] as const) {
    const name = `mg_${route.kind}_${mode}`;
    for (const bound of bounds) {
      const result = await transaction(
        pool,
        fixture.actors[actorName(route)].context,
        async (client) => {
          await client.query(`set local plan_cache_mode=${mode}`);
          return client.query({
            name,
            text,
            values: [...parameters(fixture, route), JSON.stringify(bound.rows)]
          });
        }
      );
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].fits).toBe(false);
      expect(isSubmission ? result.rows[0].item : result.rows[0].items).toBeNull();
      falseGates += 1;
    }
    await expect(
      transaction(pool, fixture.actors[actorName(route)].context, async (client) => {
        await client.query(`set local plan_cache_mode=${mode}`);
        await client.query({
          name,
          text,
          values: [...parameters(fixture, route), JSON.stringify(rows)]
        });
      })
    ).rejects.toMatchObject({ code: "22012" });
    trueFaults += 1;
  }
  expect(falseGates).toBe(18);
  expect(trueFaults).toBe(2);
  return { falseGates, trueFaults };
}

it("admits original management pages with live counts normal changes and PostgreSQL constructor gates", async () => {
  const observations: Record<string, unknown>[] = [];
  await withMigratedDatabase("mg_lists_projection", async (pool) => {
    const fixture = await seedManagementProjectionFixture(pool),
      repository = new PgSurfaceReadRepository(pool, { cursorKey: managementListCursorKey });
    const full = (kind: ManagementListKind): Route => ({ kind, limit: 100, at: null, id: null });
    let publicCalls = 0;
    async function publicPage(route: Route, cursor: string | null = null) {
      const expected = await oracle(pool, fixture, route),
        principal = fixture.principals[actorName(route)],
        manager = new ResponseAllocationManager(),
        owner = manager.openRequest(new AbortController().signal),
        before = Math.floor(Date.now() / 1000);
      try {
        const actual = await owner.produce(() =>
          repository.executeRead(principal, managementListTools[route.kind], {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            board_id: fixture.boardId,
            limit: route.limit,
            ...(cursor === null ? {} : { cursor })
          })
        );
        const after = Math.floor(Date.now() / 1000),
          data = managementObject(actual.data),
          envelope = originalManagementListEnvelope(
            route.kind,
            fixture.boardId,
            expected.rows,
            route.limit,
            principal,
            data.next_cursor,
            before,
            after,
            expected.totalVisible
          );
        expect(canonicalJson(actual)).toBe(canonicalJson(envelope));
        expect(manager.accounting.usedUnits).toBe(expected.plan.units);
        publicCalls += 1;
        observations.push({
          kind: route.kind,
          publicCall: publicCalls,
          count: (data.items as JsonValue[]).length,
          totalVisible: data.total_visible ?? null,
          held: manager.accounting.usedUnits
        });
        return { rows: expected.rows, next: data.next_cursor };
      } finally {
        close(owner);
        expect(manager.accounting.usedUnits).toBe(0);
      }
    }
    for (const kind of ["submissions", "questions"] as const) {
      const complete = await publicPage(full(kind));
      expect(complete.rows).toHaveLength(3);
      const first = await publicPage({ ...full(kind), limit: 1 });
      expect(first.rows).toHaveLength(2);
      expect(typeof first.next).toBe("string");
      const anchor = first.rows[0]!;
      await publicPage(
        { ...full(kind), limit: 1, at: anchor.cursor_at, id: anchor.cursor_id },
        first.next as string
      );
      const last = complete.rows.at(-1)!,
        tail = signManagementListTailCursor(
          kind,
          fixture.boardId,
          last,
          fixture.principals[actorName(full(kind))],
          Math.floor(Date.now() / 1000) + 86400
        );
      expect(
        (await publicPage({ ...full(kind), at: last.cursor_at, id: last.cursor_id }, tail)).rows
      ).toEqual([]);
    }
    expect(publicCalls).toBe(8);
    async function change(route: Route, label: string, mutate: () => Promise<void>) {
      const before = await verify(pool, fixture, route),
        changed = await read(pool, fixture, route, { afterMetadata: mutate });
      expect(changed.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(changed.contentCalls).toBe(1);
      expect(changed.held).toBeGreaterThan(0);
      const after = await verify(pool, fixture, route);
      observations.push({
        kind: route.kind,
        transition: label,
        before: before.expected.bound,
        after: after.expected.bound,
        refused: true
      });
    }
    await change(full("submissions"), "request", fixture.requestMainRevision);
    await fixture.replyToMainRevision(); // Replies are not list item content; do not invent a changed-list assertion.
    await change(full("submissions"), "resubmit", fixture.reviseSourceAndResubmitMain);
    await change(full("submissions"), "approve", fixture.approveMain);
    await change(full("questions"), "answer", fixture.answerFirstQuestion);
    await change(full("questions"), "follow-up", fixture.followUpFirstQuestion);
    await change(full("questions"), "answer-again", fixture.answerFirstQuestionAgain);
    await change({ ...full("submissions"), limit: 1 }, "newcomer", fixture.appendFourthSubmission);
    const oldQuestions = await oracle(pool, fixture, full("questions")),
      anchor = oldQuestions.rows[0]!,
      tailRoute = { ...full("questions"), at: anchor.cursor_at, id: anchor.cursor_id };
    let freshTail: Awaited<ReturnType<typeof read>> | undefined;
    const unseen = await read(
      pool,
      fixture,
      { ...full("questions"), limit: 1 },
      {
        afterMetadata: async () => {
          freshTail = await read(pool, fixture, tailRoute, {
            afterMetadata: fixture.appendFourthQuestion
          });
        }
      }
    );
    expect(unseen.error).toBeInstanceOf(ResponseAllocationUnavailable);
    if (!freshTail) throw new Error("coordinated question tail did not run");
    if (freshTail.error !== undefined) throw freshTail.error;
    expect((freshTail.value as { totalVisible: number }).totalVisible).toBe(4);
    expect(canonicalJson(freshTail.value)).toBe(
      canonicalJson((await oracle(pool, fixture, tailRoute)).value)
    );
    expect((freshTail.metadata[0] as { total_visible: string }).total_visible).toBe("3");
    observations.push({
      kind: "questions",
      newFrontierRefused: true,
      oldTailTotal: "3",
      freshTailTotal: 4,
      tailHeld: freshTail.held
    });
    expect(fixture.commands).toHaveLength(17);
    const finalQuestions = await oracle(pool, fixture, full("questions")),
      last = finalQuestions.rows.at(-1)!;
    const empty = await verify(pool, fixture, {
      ...full("questions"),
      at: last.cursor_at,
      id: last.cursor_id
    });
    expect(empty.expected.totalVisible).toBe("4");
    expect(empty.expected.rows).toEqual([]);
    expect(empty.actual.held).toBe(1);
    for (const kind of ["submissions", "questions"] as const) {
      const route = full(kind),
        checked = await verify(pool, fixture, route);
      for (const row of checked.expected.rows)
        expect(Object.keys(managementObject(row.item)).sort()).toEqual(
          [
            ...(kind === "submissions"
              ? SUBMISSION_LIST_KEYS
              : [...QUESTION_LIST_FLAT, "assignedOwnerIds"])
          ].sort()
        );
      const gateCounts = await faults(
        pool,
        fixture,
        route,
        checked.expected.bound as unknown as readonly Metadata[]
      );
      const manager = new ResponseAllocationManager(),
        occupied = manager.openRequest(new AbortController().signal),
        small = responseAllocationPlan({
          kind: "document",
          representation: "tool",
          canonicalBytes: 1,
          sourceId: "mg-list-small",
          sourceVersion: "1",
          sha256: "a".repeat(64)
        });
      try {
        await occupied.produce(async () => {
          for (let i = 0; i < 2048; i++) occupied.reserve(small);
        });
        const refused = await read(pool, fixture, route, { manager });
        expect(refused.error).toBeInstanceOf(ResponseAllocationUnavailable);
        expect(refused.metadataCalls).toBe(1);
        expect(refused.contentCalls).toBe(0);
        expect(refused.held).toBe(0);
        expect(manager.accounting.usedUnits).toBe(2048);
      } finally {
        close(occupied);
      }
      expect(manager.accounting.usedUnits).toBe(0);
      const disconnected = await read(pool, fixture, route, { abortAfterMetadata: true });
      expect(disconnected.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(disconnected.contentCalls).toBe(0);
      for (const context of [
        { ...fixture.actors[actorName(route)].context, organizationId: testId(480_995) },
        { ...fixture.actors[actorName(route)].context, boardIds: [] }
      ]) {
        const actual = await verify(pool, fixture, route, { context });
        observations.push({
          kind,
          context: { organization: context.organizationId, boards: context.boardIds },
          originalCount: actual.expected.rows.length
        });
      }
      observations.push({
        kind,
        gateCounts,
        bound: checked.expected.bound,
        metrics: checked.expected.metrics,
        normalizedOwners: checked.expected.normalized,
        finalUnits: manager.accounting.usedUnits
      });
    }
    // Query-only JSON shape probe. UUID-array writer/storage constraints are not
    // bypassed: no row is mutated, and native output-schema validity is not claimed.
    const numericJson = '\'[9999999999999999, null, ["Δ", "\\u0001"]]\'::jsonb';
    for (const kind of ["submissions", "questions"] as const) {
      const transformSql = (sql: string) =>
        kind === "submissions"
          ? sql.replaceAll("to_jsonb(thread.management_owner_ids)", numericJson)
          : sql
              .replaceAll("to_jsonb(assigned_owner_ids)", numericJson)
              .replaceAll("to_jsonb(page.assigned_owner_ids)", numericJson);
      const source =
        kind === "submissions" ? ORIGINAL_SUBMISSION_LIST_SQL : ORIGINAL_QUESTION_LIST_SQL;
      expect(transformSql(source)).not.toBe(source);
      const checked = await verify(pool, fixture, full(kind), {
        originalSql: transformSql(source),
        transformSql
      });
      const owners = managementObject(checked.expected.rows[0]!.item)[
        kind === "submissions" ? "management_owner_ids" : "assignedOwnerIds"
      ] as JsonValue[];
      expect(owners[0]).toBe(10000000000000000);
      expect(checked.expected.normalized[0]).toContain("9999999999999999");
      observations.push({
        kind,
        queryVariant: "numeric-carry-nested-array",
        normalized: checked.expected.normalized,
        bound: checked.expected.bound
      });
    }
    // Original question owner construction occurs only for its selected page.
    // The corresponding admitted root/hash/constructor expressions are changed
    // identically, leaving full-visible turn/answer counts and RLS intact.
    const badId = fixture.questionIds[0],
      broken = (source: string) =>
        `case when ${source}.question_id='${badId}'::uuid then ('['||${source}.question_id::text)::jsonb else to_jsonb(${source}.assigned_owner_ids) end`;
    const originalBad = ORIGINAL_QUESTION_LIST_SQL.replaceAll(
      "to_jsonb(page.assigned_owner_ids)",
      broken("page")
    );
    const badTransform = (sql: string) =>
      sql
        .replaceAll(
          "to_jsonb(assigned_owner_ids)",
          `case when question_id='${badId}'::uuid then ('['||question_id::text)::jsonb else to_jsonb(assigned_owner_ids) end`
        )
        .replaceAll("to_jsonb(page.assigned_owner_ids)", broken("page"));
    const offpage = await verify(
      pool,
      fixture,
      { ...full("questions"), limit: 1 },
      { originalSql: originalBad, transformSql: badTransform }
    );
    expect(offpage.expected.rows.some((row) => row.cursor_id === badId)).toBe(false);
    await expect(
      oracle(pool, fixture, full("questions"), fixture.actors.asker.context, originalBad)
    ).rejects.toMatchObject({ code: "22P02" });
    expect(
      (await read(pool, fixture, full("questions"), { transformSql: badTransform })).error
    ).toMatchObject({ code: "22P02" });
    observations.push({
      kind: "questions",
      queryVariant: "malformed-offpage-skipped-selected-22P02",
      offpageCount: offpage.expected.rows.length
    });
    observations.push({
      commands: fixture.commands,
      publicCalls,
      totalFalseGates: 36,
      totalTrueFaults: 4
    });
  });
  process.stdout.write(
    `MANAGEMENT_LISTS_PROJECTION_OBSERVATION ${JSON.stringify({
      observations,
      limitations: [
        "Synthetic constrained sessions; no browser/provider sign-in",
        "Numeric/malformed expressions are query-only shapes, not UUID-owner writer-reachable data",
        "No immutable edits, shadow RLS or task/admin/worker paths",
        "Small pages; no501-row PG or RSS claim; native transport is separate"
      ]
    })}\n`
  );
}, 90_000);
