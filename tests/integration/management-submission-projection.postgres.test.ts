import type { Pool, PoolClient } from "pg";
import { expect, it } from "vitest";
import {
  canonicalJson,
  type JsonValue,
  TOOL_INPUT_SCHEMA_VERSION
} from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import { PgSurfaceReadRepository } from "../../artifacts/server/src/surface-read.js";
import {
  ResponseAllocationManager,
  ResponseAllocationUnavailable,
  responseAllocationPlan
} from "../../artifacts/server/src/response-allocation.js";
import {
  SUBMISSION_PROJECTION_PREFLIGHT_SQL,
  SUBMISSION_PROJECTION_CONTENT_SQL,
  loadAdmittedSubmission,
  submissionProjectionCost,
  submissionProjectionPlan,
  type SubmissionProjectionMetadata
} from "../../artifacts/server/src/management-submission-projection.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import { testId } from "../helpers/authorized-actor.js";
import {
  seedManagementProjectionFixture,
  type ManagementProjectionFixture
} from "../helpers/management-projection-fixture.js";
import {
  originalManagementSubmission,
  managementGraph,
  managementObject,
  managementArray,
  SUBMISSION_ROOT_FLAT,
  SUBMISSION_VERSION_FLAT,
  SUBMISSION_REQUEST_FLAT,
  SUBMISSION_REPLY_FLAT,
  SUBMISSION_DISPOSITION_FLAT
} from "../helpers/management-postgres-oracle.js";

type Context = Parameters<typeof withRequestTransaction>[1];
const transaction = <T>(pool: Pool, context: Context, work: (client: PoolClient) => Promise<T>) =>
  withRequestTransaction(pool, context, work, { assumeRole: "boardagent_server" });
const close = (owner: ReturnType<ResponseAllocationManager["openRequest"]>) => {
  try {
    owner.nativeTerminal();
  } finally {
    owner.collectorSettled();
  }
};
async function read(
  pool: Pool,
  fixture: ManagementProjectionFixture,
  options: {
    context?: Context;
    memberId?: string;
    submissionId?: string;
    afterMetadata?: () => Promise<void>;
    abortAfterMetadata?: boolean;
    manager?: ResponseAllocationManager;
  } = {}
) {
  const manager = options.manager ?? new ResponseAllocationManager(),
    start = manager.accounting.usedUnits,
    abort = new AbortController(),
    owner = manager.openRequest(abort.signal);
  let metadata: SubmissionProjectionMetadata[] = [],
    retained: unknown[] = [],
    value: JsonValue | null | undefined,
    error: unknown,
    metadataCalls = 0,
    contentCalls = 0,
    held = 0;
  try {
    value = await owner.produce(() =>
      transaction(pool, options.context ?? fixture.actors.secretary.context, async (client) => {
        const port = {
          query: async (sql: string, parameters: unknown[]) => {
            if (sql === SUBMISSION_PROJECTION_CONTENT_SQL) contentCalls += 1;
            const result = await client.query(sql, parameters);
            if (sql === SUBMISSION_PROJECTION_PREFLIGHT_SQL) {
              metadataCalls += 1;
              metadata = result.rows;
              await options.afterMetadata?.();
              if (options.abortAfterMetadata) abort.abort();
            }
            if (sql === SUBMISSION_PROJECTION_CONTENT_SQL) retained = result.rows;
            return result;
          }
        } as unknown as PoolClient;
        return loadAdmittedSubmission(
          port,
          options.submissionId ?? fixture.submissionIds[0],
          options.memberId ?? fixture.actors.secretary.memberId
        );
      })
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
      "management point owner did not settle"
    );
  return { value, error, metadata, retained, metadataCalls, contentCalls, held };
}
async function verify(
  pool: Pool,
  fixture: ManagementProjectionFixture,
  options: { context?: Context; memberId?: string; submissionId?: string } = {}
) {
  const expected = await transaction(
    pool,
    options.context ?? fixture.actors.secretary.context,
    (client) =>
      originalManagementSubmission(
        client,
        options.submissionId ?? fixture.submissionIds[0],
        options.memberId ?? fixture.actors.secretary.memberId
      )
  );
  const actual = await read(pool, fixture, options);
  if (actual.error !== undefined) throw actual.error;
  expect(actual.metadata).toEqual(expected.metadata);
  expect(actual.metadataCalls).toBe(1);
  expect(canonicalJson(actual.value)).toBe(canonicalJson(expected.value));
  if (!expected.metadata[0]) {
    expect(actual.contentCalls).toBe(0);
    expect(actual.held).toBe(0);
    return { expected, actual };
  }
  const metadata = expected.metadata[0],
    plan = submissionProjectionPlan(metadata),
    metrics = submissionProjectionCost(metadata);
  expect(actual.contentCalls).toBe(1);
  expect(actual.held).toBe(plan.units);
  const payload = {
    schema_version: "boardagent.tool-result.v1",
    tool: "get_management_submission",
    status: "ok",
    reference: metadata.submission_id,
    resource_uri: null,
    data: { submission: actual.value }
  };
  const wire = {
      content: [{ type: "text", text: JSON.stringify(payload) }],
      structuredContent: payload
    },
    graph = managementGraph([wire, actual.retained]);
  expect(Buffer.byteLength(JSON.stringify(actual.retained))).toBeLessThanOrEqual(
    Number(metrics.jsonUpperBytes)
  );
  expect(BigInt(graph.properties)).toBeLessThanOrEqual(BigInt(metrics.propertyCount));
  expect(BigInt(graph.containers)).toBeLessThanOrEqual(BigInt(metrics.objectOrArrayCount));
  expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
  return {
    expected,
    actual,
    metrics,
    canonicalBytes: Buffer.byteLength(canonicalJson(payload)),
    wireBytes: Buffer.byteLength(JSON.stringify(wire))
  };
}
const fields = [
  "version_count",
  "request_count",
  "reply_count",
  "disposition_count",
  "scalar_utf8",
  "json_utf8",
  "json_properties",
  "json_containers"
] as const;
const boundParameters = (
  fixture: ManagementProjectionFixture,
  metadata: SubmissionProjectionMetadata
) => [
  fixture.submissionIds[0],
  fixture.actors.secretary.memberId,
  metadata.submission_id,
  metadata.board_id,
  metadata.row_version,
  metadata.current_version_id,
  metadata.observation_sha256,
  ...fields.map((key) => metadata[key])
];
async function constructorFaults(
  pool: Pool,
  fixture: ManagementProjectionFixture,
  metadata: SubmissionProjectionMetadata
) {
  const variants = [
    ["root", "'submission_id',thread.id", "thread.id"],
    ["version", "'version_id',version_row.id", "version_row.id"],
    ["request", "'request_id',request.id", "request.id"],
    ["reply", "'reply_id',reply.id", "reply.id"],
    ["disposition", "'disposition_id',disposition.id", "disposition.id"]
  ] as const;
  const falseBounds: Array<{ name: string; value: SubmissionProjectionMetadata }> = [];
  for (const name of [
    "submission_id",
    "board_id",
    "row_version",
    "current_version_id",
    "observation_sha256",
    ...fields
  ] as const) {
    const replacement =
      name === "observation_sha256"
        ? "0".repeat(64)
        : name === "row_version"
          ? String(BigInt(metadata.row_version) + 1n)
          : fields.includes(name as (typeof fields)[number])
            ? String(BigInt(metadata[name]!) - 1n)
            : testId(480_998);
    falseBounds.push({ name, value: { ...metadata, [name]: replacement } });
  }
  let falseGates = 0,
    trueFaults = 0;
  for (const mode of ["force_custom_plan", "force_generic_plan"] as const)
    for (const [site, needle, source] of variants) {
      expect(SUBMISSION_PROJECTION_CONTENT_SQL.split(needle)).toHaveLength(2);
      const sql = SUBMISSION_PROJECTION_CONTENT_SQL.replace(
        needle,
        `${needle}::text||(1/(length(${source}::text)-36))::text`
      );
      const selected = site === "root" ? falseBounds : falseBounds.slice(0, 1);
      const name = `mg_point_${site}_${mode}`;
      for (const control of selected) {
        const result = await transaction(pool, fixture.actors.secretary.context, async (client) => {
          await client.query(`set local plan_cache_mode=${mode}`);
          return client.query({ name, text: sql, values: boundParameters(fixture, control.value) });
        });
        expect(result.rows).toEqual([{ fits: false, view: null }]);
        falseGates += 1;
      }
      await expect(
        transaction(pool, fixture.actors.secretary.context, async (client) => {
          await client.query(`set local plan_cache_mode=${mode}`);
          await client.query({ name, text: sql, values: boundParameters(fixture, metadata) });
        })
      ).rejects.toMatchObject({ code: "22012" });
      trueFaults += 1;
    }
  expect(falseGates).toBe(34);
  expect(trueFaults).toBe(10);
  return { falseGates, trueFaults };
}

it("admits full management submission history after normal writes and skips every nested constructor on refusal", async () => {
  const observations: Record<string, unknown>[] = [];
  await withMigratedDatabase("mg_submission_projection", async (pool) => {
    const fixture = await seedManagementProjectionFixture(pool);
    const catalog = await transaction(
      pool,
      fixture.actors.secretary.context,
      async (client) =>
        (
          await client.query(
            `
      select c.relname,c.relrowsecurity,c.relforcerowsecurity,exists(select 1 from pg_index i join pg_attribute a
        on a.attrelid=i.indrelid and a.attnum=i.indkey[0] where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indisready
        and i.indnkeyatts=1 and a.attname='id') as single_id_primary_key
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname=any($1::text[]) order by c.relname`,
            [
              [
                "management_submission_threads",
                "management_submission_versions",
                "management_revision_requests",
                "management_revision_replies",
                "management_submission_dispositions",
                "management_questions",
                "management_question_turns",
                "management_question_answers"
              ]
            ]
          )
        ).rows
    );
    expect(catalog).toHaveLength(8);
    for (const row of catalog)
      expect(row).toMatchObject({
        relrowsecurity: true,
        relforcerowsecurity: true,
        single_id_primary_key: true
      });
    const initial = await verify(pool, fixture);
    observations.push({ phase: "initial", metadata: initial.expected.metadata });
    expect(managementObject(initial.expected.value!).revision_requests).toEqual([]);
    await verify(pool, fixture, {
      context: fixture.actors.management.context,
      memberId: fixture.actors.management.memberId
    });
    const unrelated = await verify(pool, fixture, {
      context: fixture.actors.asker.context,
      memberId: fixture.actors.asker.memberId
    });
    expect(unrelated.expected.value).toBeNull();
    expect(
      (await verify(pool, fixture, { submissionId: fixture.absentSubmissionId })).expected.value
    ).toBeNull();
    for (const context of [
      { ...fixture.actors.secretary.context, organizationId: testId(480_997) },
      { ...fixture.actors.secretary.context, boardIds: [] }
    ]) {
      const control = await verify(pool, fixture, { context });
      observations.push({
        phase: "context",
        organization: context.organizationId,
        boards: context.boardIds,
        originalPresent: control.expected.value !== null
      });
    }
    const transitions = [
      ["request", fixture.requestMainRevision],
      ["reply", fixture.replyToMainRevision],
      ["resubmit", fixture.reviseSourceAndResubmitMain],
      ["approve", fixture.approveMain]
    ] as const;
    for (const [name, mutate] of transitions) {
      const before = await verify(pool, fixture),
        changed = await read(pool, fixture, { afterMetadata: mutate });
      expect(changed.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(changed.contentCalls).toBe(1);
      expect(changed.held).toBeGreaterThan(0);
      expect(changed.retained).toEqual([{ fits: false, view: null }]);
      const after = await verify(pool, fixture);
      observations.push({
        phase: name,
        before: before.expected.metadata,
        after: after.expected.metadata,
        refusedBeforeConstruction: true,
        held: changed.held
      });
    }
    const complete = await verify(pool, fixture),
      metadata = complete.expected.metadata[0]!;
    expect(metadata).toMatchObject({
      version_count: "2",
      request_count: "1",
      reply_count: "1",
      disposition_count: "1"
    });
    const root = managementObject(complete.expected.value!),
      versions = managementArray(root.versions),
      requests = managementArray(root.revision_requests),
      dispositions = managementArray(root.dispositions);
    expect(Object.keys(root).sort()).toEqual(
      [
        ...SUBMISSION_ROOT_FLAT,
        "management_owner_ids",
        "versions",
        "revision_requests",
        "dispositions"
      ].sort()
    );
    for (const value of versions)
      expect(Object.keys(managementObject(value)).sort()).toEqual(
        [...SUBMISSION_VERSION_FLAT, "document_references"].sort()
      );
    for (const value of requests) {
      const request = managementObject(value);
      expect(Object.keys(request).sort()).toEqual([...SUBMISSION_REQUEST_FLAT, "replies"].sort());
      for (const reply of managementArray(request.replies))
        expect(Object.keys(managementObject(reply)).sort()).toEqual(
          [...SUBMISSION_REPLY_FLAT].sort()
        );
    }
    for (const value of dispositions)
      expect(Object.keys(managementObject(value)).sort()).toEqual(
        [...SUBMISSION_DISPOSITION_FLAT].sort()
      );
    const faults = await constructorFaults(pool, fixture, metadata);
    const manager = new ResponseAllocationManager(),
      occupied = manager.openRequest(new AbortController().signal);
    const small = responseAllocationPlan({
      kind: "document",
      representation: "tool",
      canonicalBytes: 1,
      sourceId: "mg-point-small",
      sourceVersion: "1",
      sha256: "a".repeat(64)
    });
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 2048; i++) occupied.reserve(small);
      });
      const refused = await read(pool, fixture, { manager });
      expect(refused.error).toBeInstanceOf(ResponseAllocationUnavailable);
      expect(refused.metadataCalls).toBe(1);
      expect(refused.contentCalls).toBe(0);
      expect(refused.held).toBe(0);
      expect(manager.accounting.usedUnits).toBe(2048);
    } finally {
      close(occupied);
    }
    expect(manager.accounting.usedUnits).toBe(0);
    const disconnected = await read(pool, fixture, { abortAfterMetadata: true });
    expect(disconnected.error).toBeInstanceOf(ResponseAllocationUnavailable);
    expect(disconnected.contentCalls).toBe(0);
    const revoked = await pool.query(
      "update access_token_records set revoked_at=clock_timestamp() where id=$1 and revoked_at is null returning id",
      [fixture.actors.secretary.accessTokenRecordId]
    );
    expect(revoked.rowCount).toBe(1);
    const rejectedOwner = manager.openRequest(new AbortController().signal),
      repository = new PgSurfaceReadRepository(pool, { cursorKey: Buffer.alloc(32, 1) });
    try {
      await expect(
        rejectedOwner.produce(() =>
          repository.executeRead(fixture.principals.secretary, "get_management_submission", {
            schema_version: TOOL_INPUT_SCHEMA_VERSION,
            submission_id: fixture.submissionIds[0]
          })
        )
      ).rejects.toThrow("authenticated context is no longer active");
      expect(manager.accounting.usedUnits).toBe(0);
    } finally {
      close(rejectedOwner);
    }
    expect(fixture.commands).toHaveLength(12);
    observations.push({
      phase: "complete",
      catalog,
      faults,
      commands: fixture.commands,
      metadata,
      normalizedRoots: complete.expected.normalizedRoots,
      metrics: complete.metrics,
      canonicalBytes: complete.canonicalBytes,
      wireBytes: complete.wireBytes,
      freshPublicRevokedTokenRejected: true,
      finalUsedUnits: manager.accounting.usedUnits
    });
  });
  process.stdout.write(
    `MANAGEMENT_SUBMISSION_PROJECTION_OBSERVATION ${JSON.stringify({
      observations,
      limitations: [
        "Synthetic constrained sessions; no browser authentication",
        "Direct actual-role original/admitted query proof plus one fresh public revoked-token rejection",
        "Normal small histories; no same-cost immutable data edits or arbitrary JSON writer-reachability claim",
        "PostgreSQL workspace/RSS and native delivery are separate"
      ]
    })}\n`
  );
}, 90_000);
