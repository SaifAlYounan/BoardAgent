import { expect, it } from "vitest";
import type { PoolClient } from "pg";
import { canonicalJson, sha256Hex, type JsonValue } from "../../lib/contracts/src/index.js";
import { withRequestTransaction } from "../../lib/db/src/context.js";
import {
  MINUTES_TOOL_PREFLIGHT_SQL,
  MINUTES_TOOL_CONTENT_SQL,
  loadAdmittedMinutesToolProjection,
  minutesToolProjectionCost,
  minutesToolProjectionPlan,
  type MinutesToolProjectionMetadata
} from "../../artifacts/server/src/minutes-tool-projection.js";
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
import { ORIGINAL_MINUTES_TOOL_SQL } from "../helpers/minutes-tool-original-sql.js";

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("expected original object");
  return value as Record<string, unknown>;
}
const rootKeys = [
  "minutes_id",
  "board_id",
  "meeting_id",
  "state",
  "row_version",
  "correction_of_minutes_id",
  "finalized_at",
  "cancelled_at"
] as const;
const versionKeys = [
  "version_id",
  "version",
  "canonical_schema",
  "canonical_text",
  "sha256",
  "package_base_sha256",
  "transcript_version_id",
  "transcript_sha256",
  "supersedes_id",
  "created_at"
] as const;
const packageKeys = [
  "package_id",
  "version",
  "minutes_version_id",
  "minutes_sha256",
  "package_sha256",
  "state"
] as const;
const requirementKeys = ["member_id", "seat_role", "requirement", "snapshot_sha256"] as const;
const signatureKeys = [
  "signature_id",
  "signer_member_id",
  "signer_seat_role",
  "record_sha256",
  "signed_at"
] as const;
const declarationKeys = [
  "declaration_id",
  "minutes_version_id",
  "declaration",
  "manifest_sha256",
  "declared_at"
] as const;
const values = (record: Record<string, unknown> | null, keys: readonly string[]) =>
  keys.map((key) => record?.[key] ?? null);
function keys(record: Record<string, unknown>, expected: readonly string[]) {
  expect(Object.keys(record).sort()).toEqual([...expected].sort());
}
function measure(view: Record<string, unknown>) {
  keys(view, [...rootKeys, "version", "signature_package", "action_declaration"]);
  const version = view["version"] === null ? null : object(view["version"]);
  const pkg = view["signature_package"] === null ? null : object(view["signature_package"]);
  const declaration =
    view["action_declaration"] === null ? null : object(view["action_declaration"]);
  if (version) keys(version, versionKeys);
  if (pkg) keys(pkg, [...packageKeys, "required_signers", "signatures"]);
  if (declaration) keys(declaration, declarationKeys);
  const requirements = pkg ? pkg["required_signers"] : [];
  const signatures = pkg ? pkg["signatures"] : [];
  if (!Array.isArray(requirements) || !Array.isArray(signatures))
    throw new Error("expected original package arrays");
  const q = requirements.map((item) => {
    const row = object(item);
    keys(row, requirementKeys);
    return row;
  });
  const t = signatures.map((item) => {
    const row = object(item);
    keys(row, signatureKeys);
    return row;
  });
  const scalarValues = [
    ...values(view, rootKeys),
    ...values(version, versionKeys),
    ...values(pkg, packageKeys),
    ...values(declaration, declarationKeys)
  ];
  for (const item of q) scalarValues.push(...values(item, requirementKeys));
  for (const item of t) scalarValues.push(...values(item, signatureKeys));
  let scalar = 0n;
  for (const value of scalarValues)
    if (value !== null) {
      if (typeof value !== "string" && typeof value !== "number")
        throw new Error("unexpected nonflat original scalar");
      scalar += BigInt(Buffer.byteLength(String(value), "utf8"));
    }
  return {
    version,
    pkg,
    declaration,
    q,
    t,
    scalar,
    counts: {
      row_count: "1",
      version_count: version ? "1" : "0",
      package_count: pkg ? "1" : "0",
      declaration_count: declaration ? "1" : "0",
      requirement_count: String(q.length),
      signature_count: String(t.length),
      scalar_utf8: String(scalar)
    }
  };
}
function shape(value: unknown) {
  let properties = 0n,
    containers = 0n;
  const stack: unknown[] = [value];
  while (stack.length) {
    const item = stack.pop();
    if (item === null || typeof item !== "object") continue;
    containers++;
    if (Array.isArray(item)) {
      for (const child of item) stack.push(child);
    } else {
      for (const child of Object.values(item)) stack.push(child);
      properties += BigInt(Object.keys(item).length);
    }
  }
  return { properties, containers };
}
const params = (id: string, row: MinutesToolProjectionMetadata) => [
  id,
  row.board_id,
  row.row_version,
  row.observation_sha256,
  row.row_count,
  row.version_count,
  row.package_count,
  row.declaration_count,
  row.requirement_count,
  row.signature_count,
  row.scalar_utf8
];

it("admits original minutes projections with normal finalized growth and complete guarded child construction", async () => {
  await withMigratedDatabase("minutes_tool_projection", async (pool) => {
    const fixture = await seedMinutesLineageFixture(pool),
      actor = fixture.secretary;
    const transaction = <T>(body: (client: PoolClient) => Promise<T>, context = actor.context) =>
      withRequestTransaction(pool, context, body, { assumeRole: "boardagent_server" });
    const manager = new ResponseAllocationManager(),
      reports: unknown[] = [];
    const original = (id: string, context = actor.context) =>
      transaction(
        async (client) =>
          (await client.query<{ view: JsonValue }>(ORIGINAL_MINUTES_TOOL_SQL, [id])).rows,
        context
      );
    const metadata = (id: string) =>
      transaction(
        async (client) =>
          (await client.query<MinutesToolProjectionMetadata>(MINUTES_TOOL_PREFLIGHT_SQL, [id])).rows
      );
    const catalog = (
      await pool.query(`select c.relname,c.relrowsecurity,c.relforcerowsecurity,
      exists(select 1 from pg_index i join pg_attribute a on a.attrelid=c.oid and a.attnum=i.indkey[0]
        where i.indrelid=c.oid and i.indisprimary and i.indisvalid and i.indnkeyatts=1 and a.attname='id') as id_pk
      from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public'
      and c.relname in ('minutes','minutes_versions','minutes_signature_packages','minutes_signature_requirements','minutes_signatures','minutes_action_declarations') order by c.relname`)
    ).rows;
    expect(catalog).toHaveLength(6);
    for (const row of catalog)
      expect(row).toMatchObject({ relrowsecurity: true, relforcerowsecurity: true });
    for (const table of ["minutes", "minutes_versions", "minutes_signature_packages"])
      expect(catalog.find((row) => row.relname === table)?.id_pk).toBe(true);
    expect(
      await transaction(async (client) => (await client.query("select current_user")).rows)
    ).toEqual([{ current_user: "boardagent_server" }]);

    async function read(
      id: string,
      afterMetadata?: () => Promise<unknown>,
      context = actor.context
    ) {
      const owner = manager.openRequest(new AbortController().signal),
        baseline = manager.accounting.usedUnits;
      let metadataCalls = 0,
        contentCalls = 0,
        held = baseline,
        failure: unknown,
        result: readonly { view: JsonValue }[] | undefined;
      try {
        result = await owner.produce(() =>
          transaction(async (client) => {
            const proxy = Object.create(client) as PoolClient;
            proxy.query = (async (sql: string, parameters?: unknown[]) => {
              if (sql === MINUTES_TOOL_PREFLIGHT_SQL) {
                metadataCalls++;
                const reply = await client.query(sql, parameters);
                await afterMetadata?.();
                return reply;
              }
              if (sql === MINUTES_TOOL_CONTENT_SQL) contentCalls++;
              return client.query(sql, parameters);
            }) as PoolClient["query"];
            return loadAdmittedMinutesToolProjection(proxy, id);
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
        id,
        metadataCalls,
        contentCalls,
        held,
        finalUnits: manager.accounting.usedUnits,
        failed: failure !== undefined
      });
      try {
        expect(metadataCalls).toBe(1);
        expect(manager.accounting.usedUnits).toBe(baseline);
      } catch (error) {
        if (failure !== undefined)
          throw new AggregateError([failure, error], "minutes SQL and accounting failed");
        throw error;
      }
      if (failure !== undefined) throw failure;
      return { rows: result!, metadataCalls, contentCalls, held, baseline };
    }
    async function admittedQuery(
      sql: string,
      parameters: unknown[],
      plan: ReturnType<typeof minutesToolProjectionPlan>,
      name?: string,
      mode?: string
    ) {
      const owner = manager.openRequest(new AbortController().signal);
      try {
        return await owner.produce(async () => {
          owner.reserve(plan);
          return transaction(async (client) => {
            if (mode) await client.query(`set local plan_cache_mode=${mode}`);
            return client.query({
              text: sql,
              values: parameters,
              ...(name === undefined ? {} : { name })
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
    async function verify(id: string, complete: boolean) {
      const old = await original(id);
      expect(old).toHaveLength(1);
      const view = object(old[0]!.view),
        observed = (await metadata(id))[0]!;
      const independent = measure(view);
      expect(observed).toMatchObject(independent.counts);
      expect(independent.version).not.toBeNull();
      if (complete) {
        expect(view["state"]).toBe("finalized");
        expect(independent.pkg).not.toBeNull();
        expect(independent.declaration).not.toBeNull();
        expect(independent.q).toHaveLength(1);
        expect(independent.t).toHaveLength(1);
        expect(independent.q[0]?.["member_id"]).toBe(fixture.signer.memberId);
        expect(independent.t[0]?.["signer_member_id"]).toBe(fixture.signer.memberId);
      } else {
        expect(view["state"]).toBe("published_review");
        expect(independent.pkg).toBeNull();
        expect(independent.declaration).toBeNull();
      }
      const observation = await transaction(async (client) => {
        const hash = async (value: unknown) =>
          (
            await client.query<{ hash: string }>(
              "select encode(sha256(convert_to(($1::jsonb)::text,'UTF8')),'hex') as hash",
              [JSON.stringify(value)]
            )
          ).rows[0]!.hash;
        const hashString = async (value: string) =>
          (
            await client.query<{ hash: string }>(
              "select encode(sha256(convert_to($1::text,'UTF8')),'hex') as hash",
              [value]
            )
          ).rows[0]!.hash;
        const q: string[] = [],
          t: string[] = [];
        for (const row of independent.q) q.push(await hash(values(row, requirementKeys)));
        for (const row of independent.t) t.push(await hash(values(row, signatureKeys)));
        const pointers = (
          await client.query(
            "select current_version_id,current_signature_package_id from minutes where id=$1",
            [id]
          )
        ).rows[0];
        const versionValues = values(independent.version, versionKeys);
        versionValues[3] =
          independent.version === null
            ? null
            : sha256Hex(String(independent.version["canonical_text"]));
        const rowHash = await hash([
          ...values(view, rootKeys),
          ...versionValues,
          ...values(independent.pkg, packageKeys),
          ...values(independent.declaration, declarationKeys),
          pointers.current_version_id,
          pointers.current_signature_package_id,
          await hashString(q.join("")),
          await hashString(t.join(""))
        ]);
        return hashString(rowHash);
      });
      expect(observed.observation_sha256).toBe(observation);
      const result = {
        schema_version: "boardagent.tool-result.v1",
        tool: "get_minutes",
        status: "ok",
        reference: id,
        resource_uri: `board://${actor.boardId}/minutes/${id}/versions/${String(independent.version!["version"])}`,
        data: { minutes: view }
      };
      const cost = minutesToolProjectionCost(observed),
        plan = minutesToolProjectionPlan(observed);
      const wire = {
          content: [{ type: "text", text: JSON.stringify(result) }],
          structuredContent: result
        },
        graph = shape(wire);
      expect(BigInt(Buffer.byteLength(JSON.stringify(view)))).toBeLessThanOrEqual(
        BigInt(cost.jsonUpperBytes)
      );
      expect(graph.properties).toBeLessThanOrEqual(BigInt(cost.propertyCount));
      expect(graph.containers).toBeLessThanOrEqual(BigInt(cost.objectOrArrayCount));
      expect(Buffer.byteLength(JSON.stringify(wire))).toBeLessThanOrEqual(plan.wireUpperBytes);
      expect(plan.units).toBe(1);
      const actual = await read(id);
      expect(actual.rows.map((row) => ({ view: row.view }))).toEqual(old);
      expect(actual.held).toBe(1);
      expect(canonicalJson({ ...result, data: { minutes: actual.rows[0]!.view } })).toBe(
        canonicalJson(result)
      );
      return {
        observed,
        plan,
        cost,
        old,
        scalar: independent.scalar.toString(),
        canonicalSha256: sha256Hex(canonicalJson(result))
      };
    }
    await verify(fixture.originalId, true);
    await verify(fixture.middleId, true);
    expect(fixture.currentTip()).toEqual({ minutesId: fixture.middleId, state: "finalized" });
    await fixture.appendSuccessor();
    expect(fixture.commands).toHaveLength(12);
    await verify(fixture.middleId, true);
    await verify(fixture.replacementId, false);
    const beforeGrowth = (await metadata(fixture.replacementId))[0]!;
    await expect(read(fixture.replacementId, fixture.finalizeSuccessor)).rejects.toBeInstanceOf(
      ResponseAllocationUnavailable
    );
    expect(fixture.commands).toHaveLength(16);
    expect(fixture.currentTip()).toEqual({ minutesId: fixture.replacementId, state: "finalized" });
    const final = await verify(fixture.replacementId, true);
    expect(final.observed.observation_sha256).not.toBe(beforeGrowth.observation_sha256);
    expect(final.observed.row_version).not.toBe(beforeGrowth.row_version);
    expect(BigInt(final.observed.scalar_utf8)).toBeGreaterThan(BigInt(beforeGrowth.scalar_utf8));

    // Refresh B after both normal correction/finalization transitions; no stale
    // root version or observation may make a true fault control vacuous.
    const full = await verify(fixture.middleId, true);
    const occupied = manager.openRequest(new AbortController().signal),
      small = responseAllocationPlan({
        kind: "document",
        representation: "tool",
        canonicalBytes: 1,
        sourceId: testId(336001),
        sourceVersion: "1",
        sha256: "a".repeat(64)
      });
    try {
      await occupied.produce(async () => {
        for (let i = 0; i < 2048; i++) occupied.reserve(small);
      });
      await expect(read(fixture.middleId)).rejects.toBeInstanceOf(ResponseAllocationUnavailable);
      expect(reports.at(-1)).toMatchObject({
        metadataCalls: 1,
        contentCalls: 0,
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
    expect(manager.accounting.usedUnits).toBe(0);
    const constructors = [
      "jsonb_build_object('minutes_id',minutes.minutes_id",
      "jsonb_build_object('member_id',requirement.member_id",
      "jsonb_build_object('signature_id',signature.id",
      "jsonb_build_object('declaration_id',minutes.declaration_id"
    ];
    // These exact current helper strings are reviewed before execution. No public
    // constructor is replaced at runtime: only test-local SQL clones carry faults.
    const faultFor = (sql: string, needle: string) => {
      expect(sql.includes(needle)).toBe(true);
      const scope = needle.includes("requirement.")
        ? "requirement.member_id::text"
        : needle.includes("signature.id")
          ? "signature.id::text"
          : "minutes.minutes_id::text";
      return sql.replace(
        needle,
        `jsonb_build_object('fault',1/(length(${scope})-length(${scope}))) || ${needle}`
      );
    };
    const base = params(fixture.middleId, full.observed),
      falseCases: unknown[][] = [];
    for (let index = 1; index <= 10; index++) {
      const changed = [...base];
      changed[index] =
        index === 1
          ? testId(336002)
          : index === 2
            ? String(BigInt(base[index]!) + 1n)
            : index === 3
              ? "f".repeat(64)
              : index === 10
                ? String(BigInt(base[index]!) - 1n)
                : String(BigInt(base[index]!) + 1n);
      falseCases.push(changed);
    }
    let falseControls = 0,
      trueFaults = 0;
    for (const mode of ["force_custom_plan", "force_generic_plan"]) {
      for (const [index, needle] of constructors.entries()) {
        const faulted = faultFor(MINUTES_TOOL_CONTENT_SQL, needle);
        for (const changed of falseCases) {
          const reply = await admittedQuery(
            faulted,
            changed,
            full.plan,
            `minutes_false_${mode}_${index}`,
            mode
          );
          expect(reply.rows).toHaveLength(1);
          expect(reply.rows[0]).toMatchObject({ fits: false, view: null });
          falseControls++;
        }
        await expect(
          admittedQuery(faulted, base, full.plan, `minutes_true_${mode}_${index}`, mode)
        ).rejects.toMatchObject({ code: "22012" });
        trueFaults++;
      }
    }
    expect(falseControls).toBe(80);
    expect(trueFaults).toBe(8);
    expect(manager.accounting.usedUnits).toBe(0);
    const absentId = testId(336003);
    for (const [id, context] of [
      [absentId, actor.context],
      [fixture.middleId, { ...actor.context, organizationId: testId(336004) }],
      [fixture.middleId, { ...actor.context, boardIds: [] }]
    ] as const) {
      expect(await original(id, context)).toEqual([]);
      const absent = await read(id, undefined, context);
      expect(absent.rows).toEqual([]);
      expect(absent.held).toBe(0);
      expect(absent.contentCalls).toBe(0);
    }
    const hidden = await read(fixture.middleId, () =>
      excludeMinutesLineageEndpoint(pool, actor, fixture.middleId, 336100)
    );
    expect(hidden.rows).toEqual([]);
    expect(hidden.contentCalls).toBe(1);
    expect(hidden.held).toBe(1);
    expect(await original(fixture.middleId)).toEqual([]);
    expect((await read(fixture.middleId)).held).toBe(0);
    console.info(
      JSON.stringify({
        probe: "minutes-tool-projection",
        catalog,
        normalMinutesCommands: fixture.commands,
        stateMatrix: [
          "A finalized",
          "B finalized ancestor",
          "C published_review",
          "C finalized",
          "B hidden"
        ],
        falseControls,
        trueFaults,
        completeScalarUtf8: full.scalar,
        grownScalarUtf8: final.scalar,
        canonicalSha256: full.canonicalSha256,
        reports,
        finalUnits: manager.accounting.usedUnits,
        nativeLifetime: "modeled terminal and collector signals only",
        workflowScope:
          "normal minutes no-actions/sign/finalize/correction only; synthetic exclusion evidence"
      })
    );
  });
}, 90000);
